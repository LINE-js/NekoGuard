import { hash } from "node:crypto";
import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { buildAlerts } from "./alerts.js";
import { ApiError } from "./client.js";
import { isMessage, parseAdmins, parseAnalysis, record, type Api, type Frame, type Message, type ScamAnalysis } from "./protocol.js";

interface Work {
  key: string;
  signature: string;
  message: Pick<Message, "messageId" | "channelId" | "senderId">;
  generation: number;
}

interface Notification {
  work: Work;
  analysis: ScamAnalysis;
}

interface GuardOptions {
  thresholdPercent: number;
  /** Test clock seams; production observes LINE.js's shared 10 checks/minute and 20 sends/minute. */
  checkIntervalMs?: number;
  sendIntervalMs?: number;
  adminIntervalMs?: number;
}

const MAX_QUEUE = 500;
const MAX_RECENT = 5000;
const MAX_IN_FLIGHT = 4;

export class ScamGuard extends EventEmitter {
  private ready = false;
  private supported = false;
  private userId?: string;
  private generation = 0;
  private ownMembers = new Map<string, string>();
  private channels = new Set<string>();
  private recent = new Map<string, Work>();
  private queue = new Map<string, Work>();
  private running = new Set<Promise<void>>();
  private discovering = new Set<string>();
  private notifications = new Map<string, Notification>();
  private notifying = new Map<string, Promise<void>>();
  private adminTails = new Map<string, Promise<unknown>>();
  private waits = new Map<Work, AbortController>();
  // Elapsed-time quotas must not jump or stall when the wall clock is adjusted.
  private nextCheck = 0;
  private nextSend = 0;
  private nextAdmins = 0;

  constructor(private readonly api: Api, private readonly options: GuardOptions) {
    super();
  }

  handle(frame: Frame): void {
    if (frame.type === "hello") {
      this.reset();
      this.supported = frame.protocol === 2 && Array.isArray(frame.capabilities) && frame.capabilities.includes("chat:admins");
      if (!this.supported) this.emit("fatal", "LINEJS_ADMIN_EXTENSION_REQUIRED");
      return;
    }
    if (frame.type === "auth:state" && frame.state !== "ready") {
      this.reset();
      this.emit("notice", "WAITING_FOR_LINE_LOGIN");
      return;
    }
    if (frame.type === "auth:ready") {
      if (!record(frame.profile) || typeof frame.profile.userId !== "string") return;
      this.reset();
      this.userId = frame.profile.userId;
      this.ready = this.supported;
      if (this.ready) this.emit("notice", "MONITORING_READY");
      return;
    }
    if (frame.type === "channels" && Array.isArray(frame.channels)) {
      const previous = this.channels;
      this.channels = new Set<string>();
      for (const channel of frame.channels as unknown[]) {
        if (record(channel) && channel.kind === "square" && typeof channel.channelId === "string") {
          this.channels.add(channel.channelId);
        }
      }
      let removed = false;
      for (const chatId of previous) {
        if (!this.channels.has(chatId)) {
          this.ownMembers.delete(chatId);
          removed = true;
        }
      }
      if (removed) {
        // Deleting the version makes removal permanent, even if the chat is re-added
        // before an outstanding API response arrives. Keep tracking that request.
        for (const [key, work] of this.recent) {
          if (!this.channels.has(work.message.channelId)) this.invalidate(key);
        }
      }
      return;
    }
    if (frame.type === "message:unsend" && typeof frame.chatId === "string" && typeof frame.messageId === "string") {
      const key = `${frame.chatId}:${frame.messageId}`;
      const work = this.recent.get(key);
      if (work) {
        this.invalidate(key);
        this.recent.set(key, { ...work, signature: "unsent" });
      }
      return;
    }
    if ((frame.type !== "message" && frame.type !== "message:edit") || !isMessage(frame.message) || !this.ready) return;
    const message = frame.message;
    const key = `${message.channelId}:${message.messageId}`;
    if (message.unsent || message.decryptFailed || message.contentType !== "NONE" || !message.text?.trim()) {
      this.invalidate(key);
      return;
    }
    if (message.channelKind !== "square" || !this.channels.has(message.channelId)
      || message.senderId === this.userId || message.senderId === this.ownMembers.get(message.channelId)) return;
    const signature = hash("sha256", message.text, "hex");
    const previous = this.recent.get(key);
    if (previous?.signature === signature || previous?.signature === "unsent") return;
    // Even when the replacement cannot be queued, the old result is no longer valid.
    this.invalidate(key);
    if (this.queue.size >= MAX_QUEUE) {
      this.emit("notice", "ANALYSIS_QUEUE_FULL");
      return;
    }
    // Analysis uses the backend's cached text; retain no incoming payload or sender name.
    const work: Work = {
      key, signature, generation: this.generation,
      message: { messageId: message.messageId, channelId: message.channelId, senderId: message.senderId },
    };
    this.recent.set(key, work);
    if (this.recent.size > MAX_RECENT) this.invalidate(this.recent.keys().next().value!);
    this.queue.set(key, work);
    this.start();
  }

  stop(): void {
    this.reset();
  }

  async whenIdle(): Promise<void> {
    while (this.running.size || this.notifying.size) {
      await Promise.all([...this.running, ...this.notifying.values()]);
    }
  }

  private reset(): void {
    this.generation++;
    this.ready = false;
    this.userId = undefined;
    this.channels.clear();
    this.ownMembers.clear();
    this.recent.clear();
    this.queue.clear();
    this.notifications.clear();
    for (const controller of this.waits.values()) controller.abort();
    this.waits.clear();
    // Keep pacing across account transitions: the upstream quota is server-wide.
  }

  private invalidate(key: string): void {
    const work = this.recent.get(key);
    if (work) this.waits.get(work)?.abort();
    this.recent.delete(key);
    this.queue.delete(key);
    this.notifications.delete(key);
  }

  private async wait(work: Work, milliseconds: number): Promise<void> {
    const controller = new AbortController();
    this.waits.set(work, controller);
    try {
      await delay(milliseconds, undefined, { signal: controller.signal });
    } finally {
      this.waits.delete(work);
    }
  }

  private current(work: Work): boolean {
    return this.ready && work.generation === this.generation && this.recent.get(work.key) === work
      && this.channels.has(work.message.channelId);
  }

  private start(): void {
    for (const work of this.queue.values()) {
      if (!this.ready || this.running.size >= MAX_IN_FLIGHT) break;
      const chatId = work.message.channelId;
      // Only the discovery leader occupies a worker; its followers stay bounded by MAX_QUEUE.
      if (!this.ownMembers.has(chatId)) {
        if (this.discovering.has(chatId)) continue;
      }
      this.queue.delete(work.key);
      const task = this.inspect(work).catch(error => this.failed(work, error)).finally(() => {
        this.running.delete(task);
        this.start();
      });
      this.running.add(task);
    }
  }

  private failed(work: Work, error: unknown): void {
    if (!this.current(work)) return;
    // Never expose untrusted response text or message contents through logs.
    const code = error instanceof ApiError ? error.code : "ANALYSIS_OR_NOTIFICATION_FAILED";
    this.emit("notice", code);
    if (code === "SCAM_CHECK_UNAVAILABLE" || code === "UNKNOWN_TYPE") {
      this.stop();
      this.emit("fatal", code);
    }
  }

  private startNotifications(): void {
    for (const [key, { work, analysis }] of this.notifications) {
      if (!this.ready || this.notifying.size >= MAX_IN_FLIGHT) break;
      if (!this.current(work)) {
        this.notifications.delete(key);
        continue;
      }
      const chatId = work.message.channelId;
      // Waiting jobs in a busy chat must not occupy other notification lanes.
      if (this.notifying.has(chatId)) continue;
      this.notifications.delete(key);
      this.startNotification(work, analysis);
    }
  }

  private startNotification(work: Work, analysis: ScamAnalysis): void {
    const chatId = work.message.channelId;
    const task = this.withAdmins(chatId, () => this.notify(work, analysis))
      .catch(error => this.failed(work, error)).finally(() => {
        this.notifying.delete(chatId);
        this.startNotifications();
      });
    this.notifying.set(chatId, task);
  }

  private withAdmins<T>(chatId: string, action: () => Promise<T>): Promise<T> {
    // A lookup revokes only this chat's mention grants. Hold its lane through all sends.
    const task = (this.adminTails.get(chatId) ?? Promise.resolve()).then(action);
    const tail = task.catch(() => undefined).finally(() => {
      if (this.adminTails.get(chatId) === tail) this.adminTails.delete(chatId);
    });
    this.adminTails.set(chatId, tail);
    return task;
  }

  private async inspect(work: Work): Promise<void> {
    if (!this.current(work)) return;
    const message = work.message;
    if (!this.ownMembers.has(message.channelId)) {
      this.discovering.add(message.channelId);
      try {
        await this.withAdmins(message.channelId, async () => {
          if (this.current(work) && !this.ownMembers.has(message.channelId)) await this.fetchAdmins(work);
        });
      } finally {
        this.discovering.delete(message.channelId);
        // Let the leader dispatch first, then admit followers using the resolved identity.
        queueMicrotask(() => this.start());
      }
    }
    if (!this.current(work) || !this.ownMembers.has(message.channelId)) return;
    // OpenChat's p… identity differs from the account's u… identity, including phone-originated sends.
    if (message.senderId === this.userId || message.senderId === this.ownMembers.get(message.channelId)) return;
    // Recheck after waking: other workers or a delayed event loop may have
    // consumed the slot. Reserve only at actual dispatch, never in the future.
    while (this.nextCheck > performance.now()) {
      await this.wait(work, this.nextCheck - performance.now());
      if (!this.current(work)) return;
    }
    if (!this.current(work)) return;
    this.nextCheck = performance.now() + (this.options.checkIntervalMs ?? 6100);
    const result = await this.api.request("scam:check", {
      chatId: message.channelId, messageId: message.messageId,
    }, "scam:result");
    if (!this.current(work)) return;
    const analysis = parseAnalysis(result, message);
    if (analysis.probability < this.options.thresholdPercent / 100) return;
    // Give older runnable notifications priority, then use a free lane without
    // charging a waiting-queue slot to a notification that can start immediately.
    this.startNotifications();
    if (this.notifying.size < MAX_IN_FLIGHT && !this.notifying.has(message.channelId)) {
      this.startNotification(work, analysis);
      return;
    }
    if (this.notifications.size >= MAX_QUEUE) {
      this.emit("notice", "NOTIFICATION_QUEUE_FULL");
      return;
    }
    this.notifications.set(work.key, { work, analysis });
  }

  private async notify(work: Work, analysis: ScamAnalysis): Promise<void> {
    if (!this.current(work)) return;
    const message = work.message;
    // Roles may change while Jev is answering; never reuse the discovery list for notification.
    const members = await this.fetchAdmins(work);
    if (!members) return;
    if (message.senderId === members.ownMemberId) return;
    const alerts = buildAlerts(message, analysis, members.admins);
    let sent = 0;
    for (const alert of alerts) {
      while (this.nextSend > performance.now()) {
        await this.wait(work, this.nextSend - performance.now());
        if (!this.current(work)) return;
      }
      if (!this.current(work)) return;
      this.nextSend = performance.now() + (this.options.sendIntervalMs ?? 3100);
      await this.api.request("message:send", { chatId: message.channelId, ...alert }, "sent");
      if (!this.current(work)) return;
      sent += alert.mentions.length;
      this.emit("alert", { probability: analysis.probability, mentioned: sent, total: members.admins.length });
    }
  }

  private async fetchAdmins(work: Work) {
    while (this.nextAdmins > performance.now()) {
      await this.wait(work, this.nextAdmins - performance.now());
      if (!this.current(work)) return;
    }
    if (!this.current(work)) return;
    this.nextAdmins = performance.now() + (this.options.adminIntervalMs ?? 6100);
    const frame = await this.api.request("chat:admins:get", { chatId: work.message.channelId }, "chat:admins");
    if (!this.current(work)) return;
    const members = parseAdmins(frame, work.message.channelId);
    this.ownMembers.set(work.message.channelId, members.ownMemberId);
    return members;
  }
}
