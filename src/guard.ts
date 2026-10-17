import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { buildAlerts } from "./alerts.js";
import { ApiError } from "./client.js";
import { isMessage, parseAdmins, parseAnalysis, record, type Api, type Frame, type Message } from "./protocol.js";

interface Work {
  key: string;
  signature: string;
  message: Message;
  generation: number;
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

export class ScamGuard extends EventEmitter {
  private ready = false;
  private supported = false;
  private userId?: string;
  private generation = 0;
  private ownMembers = new Map<string, string>();
  private channels = new Set<string>();
  private recent = new Map<string, Work>();
  private queue = new Map<string, Work>();
  private running?: Promise<void>;
  private controller = new AbortController();
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
      this.channels.clear();
      for (const channel of frame.channels as unknown[]) {
        if (record(channel) && channel.kind === "square" && typeof channel.channelId === "string") {
          this.channels.add(channel.channelId);
        }
      }
      return;
    }
    if (frame.type === "message:unsend" && typeof frame.chatId === "string" && typeof frame.messageId === "string") {
      const key = `${frame.chatId}:${frame.messageId}`;
      const work = this.recent.get(key);
      if (work) {
        // Invalidate an analysis already in flight as well as an item still waiting in the queue.
        this.recent.set(key, { ...work, signature: "unsent" });
        this.queue.delete(key);
      }
      return;
    }
    if ((frame.type !== "message" && frame.type !== "message:edit") || !isMessage(frame.message) || !this.ready) return;
    const message = frame.message;
    const key = `${message.channelId}:${message.messageId}`;
    if (message.unsent || message.decryptFailed || message.contentType !== "NONE" || !message.text?.trim()) {
      this.recent.delete(key);
      this.queue.delete(key);
      return;
    }
    if (message.channelKind !== "square" || !this.channels.has(message.channelId)
      || message.senderId === this.userId || message.senderId === this.ownMembers.get(message.channelId)) return;
    const signature = createHash("sha256").update(message.text).digest("hex");
    const previous = this.recent.get(key);
    if (previous?.signature === signature || previous?.signature === "unsent") return;
    if (!this.queue.has(key) && this.queue.size >= MAX_QUEUE) {
      this.emit("notice", "ANALYSIS_QUEUE_FULL");
      return;
    }
    const work: Work = { key, signature, message, generation: this.generation };
    this.recent.delete(key);
    this.recent.set(key, work);
    if (this.recent.size > MAX_RECENT) this.recent.delete(this.recent.keys().next().value!);
    this.queue.set(key, work);
    this.start();
  }

  stop(): void {
    this.reset();
  }

  async whenIdle(): Promise<void> {
    while (this.running) await this.running;
  }

  private reset(): void {
    this.generation++;
    this.ready = false;
    this.userId = undefined;
    this.channels.clear();
    this.ownMembers.clear();
    this.recent.clear();
    this.queue.clear();
    this.controller.abort();
    this.controller = new AbortController();
    // Keep pacing across account transitions: the upstream quota is server-wide.
  }

  private current(work: Work): boolean {
    return this.ready && work.generation === this.generation && this.recent.get(work.key) === work
      && this.channels.has(work.message.channelId);
  }

  private start(): void {
    if (this.running || !this.ready) return;
    this.running = this.drain().finally(() => {
      this.running = undefined;
      if (this.queue.size && this.ready) this.start();
    });
  }

  private async drain(): Promise<void> {
    while (this.ready && this.queue.size) {
      const work = this.queue.values().next().value!;
      this.queue.delete(work.key);
      try {
        await this.inspect(work);
      } catch (error) {
        if (!this.current(work)) continue;
        // Never expose untrusted response text or message contents through logs.
        const code = error instanceof ApiError ? error.code : "ANALYSIS_OR_NOTIFICATION_FAILED";
        this.emit("notice", code);
        if (code === "SCAM_CHECK_UNAVAILABLE" || code === "UNKNOWN_TYPE") {
          this.stop();
          this.emit("fatal", code);
        }
      }
    }
  }

  private async inspect(work: Work): Promise<void> {
    if (!this.current(work)) return;
    const message = work.message;
    if (!this.ownMembers.has(message.channelId)) {
      if (!await this.fetchAdmins(work)) return;
    }
    // OpenChat's p… identity differs from the account's u… identity, including phone-originated sends.
    if (message.senderId === this.userId || message.senderId === this.ownMembers.get(message.channelId)) return;
    const signal = this.controller.signal;
    const checkWait = this.nextCheck - Date.now();
    if (checkWait > 0) await delay(checkWait, undefined, { signal });
    if (!this.current(work)) return;
    this.nextCheck = Date.now() + (this.options.checkIntervalMs ?? 6100);
    const result = await this.api.request("scam:check", {
      chatId: message.channelId, messageId: message.messageId,
    }, "scam:result");
    if (!this.current(work)) return;
    const analysis = parseAnalysis(result, message);
    if (analysis.probability < this.options.thresholdPercent / 100) return;
    // Roles may change while Jev is answering; never reuse the discovery list for notification.
    const members = await this.fetchAdmins(work);
    if (!members) return;
    if (message.senderId === members.ownMemberId) return;
    const alerts = buildAlerts(message, analysis, members.admins);
    let sent = 0;
    for (const alert of alerts) {
      const sendWait = this.nextSend - Date.now();
      if (sendWait > 0) await delay(sendWait, undefined, { signal });
      if (!this.current(work)) return;
      this.nextSend = Date.now() + (this.options.sendIntervalMs ?? 3100);
      await this.api.request("message:send", { chatId: message.channelId, ...alert }, "sent");
      if (!this.current(work)) return;
      sent += alert.mentions.length;
      this.emit("alert", { probability: analysis.probability, mentioned: sent, total: members.admins.length });
    }
  }

  private async fetchAdmins(work: Work) {
    const wait = this.nextAdmins - Date.now();
    if (wait > 0) await delay(wait, undefined, { signal: this.controller.signal });
    if (!this.current(work)) return;
    this.nextAdmins = Date.now() + (this.options.adminIntervalMs ?? 6100);
    const frame = await this.api.request("chat:admins:get", { chatId: work.message.channelId }, "chat:admins");
    if (!this.current(work)) return;
    const members = parseAdmins(frame, work.message.channelId);
    this.ownMembers.set(work.message.channelId, members.ownMemberId);
    return members;
  }
}
