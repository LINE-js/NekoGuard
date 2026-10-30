import { hash } from "node:crypto";
import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { buildAlerts, buildJoinAlerts, buildMark, buildNoteSubject, buildNoteMark, buildNoteAlerts, type Alert, type AlertBasis } from "./alerts.js";
import { ApiError } from "./client.js";
import { isAdminLikeName } from "./names.js";
import {
  isMessage, parseAdmins, parseAnalysis, parseAvatar, parseJoin, parseMembership, parseNote, record,
  type Admin, type Api, type Frame, type JoinedMember, type Message, type ScamAnalysis,
} from "./protocol.js";

interface Work {
  key: string;
  signature: string;
  message: Pick<Message, "messageId" | "channelId" | "senderId">;
  /** Kept only until the analysis starts: for the local Jev check and the reviewer. */
  text?: string;
  generation: number;
  /** Set when the work is a member join rather than a message; `message.senderId` is the joiner. */
  join?: JoinedMember;
  /** Bounded author label, retained only until the note analysis starts. */
  noteSubject?: string;
}

export type AlertEvent =
  | { kind: "scam"; probability: number }
  /** Stage one: the message was marked in the chat without mentioning anyone. */
  | { kind: "mark"; probability: number }
  | { kind: "join"; crown: number | null | undefined; nameHit: boolean }
  | { kind: "note"; probability: number };

interface Notification {
  work: Work;
  build: (admins: readonly Admin[]) => Alert[];
  event: AlertEvent;
  /** Queue key when one work sends more than one notification (the stage-one mark). */
  key?: string;
  /** Sent without an administrator lookup or mentions. */
  mark?: boolean;
}

interface GuardOptions {
  thresholdPercent: number;
  crownThresholdPercent: number;
  /** At or above this Jev percentage the admins are mentioned at once, skipping the intent review. */
  directAlertPercent?: number;
  /** Judges a picture by a validated OpenChat CDN path when the backend cannot; null means no picture. */
  crown?: (picturePath: string) => Promise<number | null>;
  /** Judges message text locally; without it the backend's `scam:check` is used. */
  scam?: (text: string) => Promise<ScamAnalysis>;
  /** Optional second opinion on a flagged message's intent; false drops the alert. */
  review?: (text: string, probability: number) => Promise<boolean>;
  /** Test clock seams; production observes the backend's 10 checks/minute (patched LINE.js only), 20 sends/minute and 10 lookups/second. */
  checkIntervalMs?: number;
  sendIntervalMs?: number;
  adminIntervalMs?: number;
  membershipIntervalMs?: number;
}

const MAX_QUEUE = 500;
const MAX_RECENT = 5000;
const MAX_IN_FLIGHT = 4;
const MARK_SUFFIX = "#mark";

export class ScamGuard extends EventEmitter {
  private ready = false;
  private supported = false;
  private joinsSupported = false;
  private avatarViaBackend = false;
  /** Newer LINE.js (built-in joins) removed `scam:check`; asking it would only time out. */
  private scamViaBackend = false;
  /** `chat:membership:get` finds the own OpenChat identity without paging every member. */
  private membershipLookup = false;
  private joinSequence = 0;
  private userId?: string;
  private generation = 0;
  private ownMembers = new Map<string, string>();
  private channels = new Map<string, "square" | "group">();
  private recent = new Map<string, Work>();
  private queue = new Map<string, Work>();
  private running = new Set<Promise<void>>();
  /** Works awaiting an intent review; bounded by MAX_IN_FLIGHT separately from Jev checks. */
  private reviewing = 0;
  private reviewWaiters = new Set<() => void>();
  private discovering = new Set<string>();
  private notifications = new Map<string, Notification>();
  private notifying = new Map<string, Promise<void>>();
  private adminTails = new Map<string, Promise<unknown>>();
  private waits = new Map<Work, AbortController>();
  // Elapsed-time quotas must not jump or stall when the wall clock is adjusted.
  private readonly checkQuotas: readonly Quota[];
  private readonly adminQuotas: readonly Quota[];
  private readonly membershipQuotas: readonly Quota[];
  private readonly sendQuotas: readonly Quota[];

  constructor(private readonly api: Api, private readonly options: GuardOptions) {
    super();
    // Upstream limits are sliding windows, so a burst may go out at once instead of one per interval.
    // Windows carry a margin for the time a request takes to reach the server.
    const seam = (intervalMs: number | undefined, ...production: Quota[]) => intervalMs === undefined ? production : [new Quota(1, intervalMs)];
    // Per connection, `chat:admins:get` and `chat:membership:get` share 10/second.
    const lookups = new Quota(10, 1100);
    this.checkQuotas = seam(options.checkIntervalMs, new Quota(10, 61_000));
    // Each administrator lookup pages through every member on LINE: keep the 10/minute cap on LINE load.
    this.adminQuotas = seam(options.adminIntervalMs, new Quota(10, 61_000), lookups);
    this.membershipQuotas = seam(options.membershipIntervalMs, lookups);
    // LINE.js defaults: 20/minute across bots and 5/second per connection.
    this.sendQuotas = seam(options.sendIntervalMs, new Quota(20, 61_000), new Quota(5, 1100));
  }

  handle(frame: Frame): void {
    if (frame.type === "hello") {
      this.reset();
      this.supported = frame.protocol === 2 && Array.isArray(frame.capabilities) && frame.capabilities.includes("chat:admins");
      if (!this.supported) this.emit("fatal", "LINEJS_ADMIN_EXTENSION_REQUIRED");
      const capabilities = frame.capabilities as unknown[];
      // The NekoGuard patch also judges pictures; newer LINE.js only announces joins.
      this.avatarViaBackend = this.supported && capabilities.includes("member:join");
      this.joinsSupported = this.avatarViaBackend || (this.supported && capabilities.includes("chat:member-joined"));
      this.scamViaBackend = this.supported && !capabilities.includes("chat:member-joined");
      this.membershipLookup = this.supported && capabilities.includes("chat:members");
      // Scam monitoring still works against an older extension; only join checks are unavailable.
      if (this.supported && !this.joinsSupported) this.emit("notice", "LINEJS_MEMBER_JOIN_EXTENSION_REQUIRED");
      else if (this.joinsSupported && !this.avatarViaBackend && !this.options.crown) this.emit("notice", "CROWN_CHECK_DISABLED");
      if (this.supported && !this.scamViaBackend && !this.options.scam) this.emit("notice", "SCAM_CHECK_DISABLED");
      if (this.supported && capabilities.includes("chat:note-posted") && (!this.options.scam || !this.options.review)) {
        this.emit("notice", "NOTE_CHECK_DISABLED");
      }
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
      this.channels = new Map<string, "square" | "group">();
      for (const channel of frame.channels as unknown[]) {
        if (record(channel) && (channel.kind === "square" || channel.kind === "group") && typeof channel.channelId === "string") {
          this.channels.set(channel.channelId, channel.kind);
        }
      }
      let removed = false;
      for (const [chatId, kind] of previous) {
        if (this.channels.get(chatId) !== kind) {
          this.ownMembers.delete(chatId);
          removed = true;
        }
      }
      if (removed) {
        // Deleting the version makes removal permanent, even if the chat is re-added
        // before an outstanding API response arrives. Keep tracking that request.
        for (const [key, work] of this.recent) {
          if (this.channels.get(work.message.channelId) !== previous.get(work.message.channelId)) this.invalidate(key);
        }
      }
      return;
    }
    if (frame.type === "message:unsend" && typeof frame.chatId === "string" && typeof frame.messageId === "string") {
      let key = `${frame.chatId}:${frame.messageId}`;
      let work = this.recent.get(key);
      // Notes are deduplicated by postId, but take-backs refer to their notification's messageId.
      if (!work) {
        for (const candidate of this.recent.values()) {
          if (candidate.message.channelId === frame.chatId && candidate.message.messageId === frame.messageId) {
            work = candidate;
            key = candidate.key;
            break;
          }
        }
      }
      if (work) {
        this.invalidate(key);
        this.recent.set(key, { ...work, signature: "unsent" });
      }
      return;
    }
    if (frame.type === "member:join" || frame.type === "chat:member-joined") {
      const member = parseJoin(frame);
      if (!member || !this.ready || !this.joinsSupported || this.channels.get(member.chatId) !== "square"
        || member.userId === this.ownMembers.get(member.chatId)) return;
      const key = `join:${member.chatId}:${member.userId}`;
      // A rejoin supersedes any check still pending for the earlier join.
      this.invalidate(key);
      if (this.queue.size >= MAX_QUEUE) {
        this.emit("notice", "ANALYSIS_QUEUE_FULL");
        return;
      }
      const work: Work = {
        key, signature: `join:${++this.joinSequence}`, generation: this.generation, join: member,
        message: { messageId: "", channelId: member.chatId, senderId: member.userId },
      };
      this.track(work);
      return;
    }
    if (frame.type === "chat:note-posted") {
      const note = parseNote(frame);
      if (!note || !this.ready || !this.options.scam || !this.options.review || !this.channels.has(note.chatId)
        || (note.senderId !== undefined && (note.senderId === this.userId || note.senderId === this.ownMembers.get(note.chatId)))) return;
      if (note.error) {
        this.emit("notice", note.error);
        return;
      }
      if (!note.postId || !note.text?.trim()) return;
      const key = `note:${note.chatId}:${note.postId}`;
      if (this.recent.has(key)) return;
      if (this.queue.size >= MAX_QUEUE) {
        this.emit("notice", "ANALYSIS_QUEUE_FULL");
        return;
      }
      this.track({
        key, signature: "note", generation: this.generation, text: note.text,
        message: { messageId: note.messageId ?? "", channelId: note.chatId, senderId: note.senderId ?? "" },
        noteSubject: buildNoteSubject(note.senderName ?? ""),
      });
      return;
    }
    if ((frame.type !== "message" && frame.type !== "message:edit") || !isMessage(frame.message) || !this.ready
      || (!this.options.scam && !this.scamViaBackend)) return;
    const message = frame.message;
    const key = `${message.channelId}:${message.messageId}`;
    if (message.unsent || message.decryptFailed || message.contentType !== "NONE" || !message.text?.trim()) {
      this.invalidate(key);
      return;
    }
    if (message.channelKind !== "square" || this.channels.get(message.channelId) !== "square"
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
    // Retain no sender name; the text only when NekoGuard itself must read it.
    const work: Work = {
      key, signature, generation: this.generation,
      message: { messageId: message.messageId, channelId: message.channelId, senderId: message.senderId },
      // Dropped as soon as the analysis reads it.
      ...(this.options.scam || this.options.review ? { text: message.text } : {}),
    };
    this.track(work);
  }

  private track(work: Work): void {
    this.recent.set(work.key, work);
    if (this.recent.size > MAX_RECENT) this.invalidate(this.recent.keys().next().value!);
    this.queue.set(work.key, work);
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
    this.notifications.delete(`${key}${MARK_SUFFIX}`);
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
      // Works in intent review have handed their analysis slot back.
      if (!this.ready || this.running.size - this.reviewing >= MAX_IN_FLIGHT) break;
      const chatId = work.message.channelId;
      // Only the discovery leader occupies a worker; its followers stay bounded by MAX_QUEUE.
      if (this.channels.get(chatId) === "square" && !this.ownMembers.has(chatId)) {
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
    for (const [key, notification] of this.notifications) {
      const work = notification.work;
      if (!this.ready || this.notifying.size >= MAX_IN_FLIGHT) break;
      if (!this.current(work)) {
        this.notifications.delete(key);
        continue;
      }
      const chatId = work.message.channelId;
      // Waiting jobs in a busy chat must not occupy other notification lanes.
      if (this.notifying.has(chatId)) continue;
      this.notifications.delete(key);
      this.startNotification(notification);
    }
  }

  private startNotification(notification: Notification): void {
    const chatId = notification.work.message.channelId;
    const task = this.withAdmins(chatId, () => this.notify(notification))
      .catch(error => this.failed(notification.work, error)).finally(() => {
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
    // Held only for this one analysis: never kept in the recent-work table.
    const text = work.text;
    work.text = undefined;
    const noteSubject = work.noteSubject;
    work.noteSubject = undefined;
    if (!this.current(work)) return;
    const message = work.message;
    const square = this.channels.get(message.channelId) === "square";
    if (square && !this.ownMembers.has(message.channelId)) {
      this.discovering.add(message.channelId);
      try {
        if (this.membershipLookup) {
          // Grants are untouched, so this need not wait behind the chat's notification lane.
          await this.fetchOwnMember(work);
        } else {
          await this.withAdmins(message.channelId, async () => {
            if (this.current(work) && !this.ownMembers.has(message.channelId)) await this.fetchAdmins(work);
          });
        }
      } finally {
        this.discovering.delete(message.channelId);
        // Let the leader dispatch first, then admit followers using the resolved identity.
        queueMicrotask(() => this.start());
      }
    }
    if (!this.current(work) || (square && !this.ownMembers.has(message.channelId))) return;
    // OpenChat's p… identity differs from the account's u… identity, including phone-originated sends.
    if (message.senderId === this.userId || message.senderId === this.ownMembers.get(message.channelId)) return;
    if (work.join) return this.inspectJoin(work, work.join);
    let analysis: ScamAnalysis;
    if (this.options.scam) {
      // NekoGuard calls TypeSafe itself: only the backend's `scam:check` has the shared 10/minute quota.
      try {
        analysis = await this.options.scam(text ?? "");
      } catch (error) {
        if (!this.current(work)) return;
        // Only our own fixed codes: never the text, response body or key.
        this.emit("notice", error instanceof Error && /^SCAM_[A-Z_]+$/.test(error.message) ? error.message : "SCAM_CHECK_FAILED");
        return;
      }
      if (!this.current(work)) return;
    } else {
      const result = await this.paced(work, this.checkQuotas, () => this.api.request("scam:check", {
        chatId: message.channelId, messageId: message.messageId,
      }, "scam:result"));
      if (!result || !this.current(work)) return;
      analysis = parseAnalysis(result, message);
    }
    if (analysis.probability < this.options.thresholdPercent / 100) return;
    if (noteSubject) {
      // Notes always use both stages, even above the message-only direct-alert threshold.
      this.enqueue({
        work, key: `${work.key}${MARK_SUFFIX}`, mark: true,
        event: { kind: "mark", probability: analysis.probability },
        build: () => [buildNoteMark(noteSubject, analysis)],
      });
      let verdict: boolean;
      try {
        verdict = await this.review(work, text!, analysis.probability);
      } catch (error) {
        if (!this.current(work)) return;
        this.emit("notice", error instanceof Error && /^REVIEW_[A-Z_]+$/.test(error.message) ? error.message : "REVIEW_FAILED");
        return;
      }
      if (!this.current(work)) return;
      this.emit("review", { probability: analysis.probability, scam: verdict });
      if (verdict) this.enqueue({
        work, mark: !square, event: { kind: "note", probability: analysis.probability },
        build: admins => buildNoteAlerts(noteSubject, analysis, square ? admins : undefined),
      });
      return;
    }
    // Very high scores, or no reviewer at all, mention the admins at once without a separate mark.
    const direct = this.options.directAlertPercent !== undefined
      && analysis.probability >= this.options.directAlertPercent / 100;
    if (direct || !this.options.review || !text?.trim()) {
      this.enqueue({
        work, event: { kind: "scam", probability: analysis.probability },
        build: admins => buildAlerts(message, analysis, admins),
      });
      return;
    }
    // Stage one: mark the message in the chat right away, mentioning no one.
    this.enqueue({
      work, key: `${work.key}${MARK_SUFFIX}`, mark: true,
      event: { kind: "mark", probability: analysis.probability },
      build: () => [buildMark(message, analysis)],
    });
    // Stage two: only a scam intent in the wording brings the administrators in.
    let verdict: boolean | undefined;
    try {
      verdict = await this.review(work, text, analysis.probability);
    } catch (error) {
      // A failed review must not hide a detector hit: mention the admins and say so.
      if (!this.current(work)) return;
      this.emit("notice", error instanceof Error && /^REVIEW_[A-Z_]+$/.test(error.message) ? error.message : "REVIEW_FAILED");
      verdict = undefined;
    }
    if (!this.current(work)) return;
    this.emit("review", { probability: analysis.probability, scam: verdict !== false });
    if (verdict === false) return;
    const basis: AlertBasis = verdict === true ? "intent" : "unreviewed";
    this.enqueue({
      work, event: { kind: "scam", probability: analysis.probability },
      build: admins => buildAlerts(message, analysis, admins, basis),
    });
  }

  private async inspectJoin(work: Work, member: JoinedMember): Promise<void> {
    // The picture first (Jev), then the name (local); either finding alone alerts the admins.
    let crown: number | null | undefined;
    if (this.avatarViaBackend) {
      try {
        const result = await this.paced(work, this.checkQuotas,
          () => this.api.request("avatar:check", { chatId: member.chatId, memberId: member.userId }, "avatar:result"));
        if (!result || !this.current(work)) return;
        crown = parseAvatar(result, member);
      } catch (error) {
        if (!this.current(work)) return;
        // An unjudged picture must not suppress a name finding.
        this.emit("notice", error instanceof ApiError ? error.code : "AVATAR_CHECK_FAILED");
      }
    } else if (member.picturePath === undefined) {
      this.emit("notice", "CROWN_PICTURE_INVALID");
    } else if (this.options.crown) {
      try {
        crown = await this.options.crown(member.picturePath);
        if (!this.current(work)) return;
      } catch (error) {
        if (!this.current(work)) return;
        // Only our own fixed codes: never a response body, picture or key.
        this.emit("notice", error instanceof Error && /^CROWN_[A-Z_]+$/.test(error.message) ? error.message : "CROWN_CHECK_FAILED");
      }
    }
    const crownHit = typeof crown === "number" && crown >= this.options.crownThresholdPercent / 100;
    const nameHit = isAdminLikeName(member.displayName);
    // Every judged join is reported, alerting or not; ids and results only, never the name.
    this.emit("join", { chatId: member.chatId, memberId: member.userId, crown, crownHit, nameHit, alert: crownHit || nameHit });
    if (!crownHit && !nameHit) return;
    this.enqueue({
      work, event: { kind: "join", crown, nameHit },
      build: admins => buildJoinAlerts(member, { crown, crownHit, nameHit }, admins),
    });
  }

  /**
   * Runs the intent review in its own pool and hands the analysis slot back, so a burst of flagged
   * messages waiting on the model does not stop Jev from checking everything else. When the review
   * pool is full the work keeps its analysis slot, which bounds the total in flight.
   */
  private async review(work: Work, text: string, probability: number): Promise<boolean> {
    while (this.reviewing >= MAX_IN_FLIGHT) {
      if (!this.current(work)) throw new Error("REVIEW_CANCELLED");
      const controller = new AbortController();
      const { promise, resolve } = Promise.withResolvers<void>();
      controller.signal.addEventListener("abort", () => resolve(), { once: true });
      const wake = () => controller.abort();
      this.reviewWaiters.add(wake);
      // Invalidation aborts this like any other local wait.
      this.waits.set(work, controller);
      try {
        await promise;
      } finally {
        this.reviewWaiters.delete(wake);
        this.waits.delete(work);
      }
    }
    if (!this.current(work)) throw new Error("REVIEW_CANCELLED");
    this.reviewing++;
    this.start();
    try {
      return await this.options.review!(text, probability);
    } finally {
      this.reviewing--;
      // Every waiter rechecks; a stale one leaves without taking the slot.
      for (const wakeWaiter of this.reviewWaiters) wakeWaiter();
    }
  }

  /**
   * Waits until every quota has room, then charges them and dispatches in the same turn, so neither
   * another worker nor an invalidation can slip in between; undefined when the work became stale.
   */
  private async paced(work: Work, quotas: readonly Quota[], dispatch: () => Promise<Frame>): Promise<Frame | undefined> {
    // Recheck after waking: other workers or a delayed event loop may have
    // consumed the room. Reserve only at actual dispatch, never in the future.
    while (this.current(work)) {
      const now = performance.now();
      const delay = Math.max(...quotas.map(quota => quota.delay(now)));
      if (delay <= 0) {
        for (const quota of quotas) quota.take(now);
        return dispatch();
      }
      await this.wait(work, delay);
    }
    return undefined;
  }

  private enqueue(notification: Notification): void {
    const chatId = notification.work.message.channelId;
    // Give older runnable notifications priority, then use a free lane without
    // charging a waiting-queue slot to a notification that can start immediately.
    this.startNotifications();
    if (this.notifying.size < MAX_IN_FLIGHT && !this.notifying.has(chatId)) {
      this.startNotification(notification);
      return;
    }
    if (this.notifications.size >= MAX_QUEUE) {
      this.emit("notice", "NOTIFICATION_QUEUE_FULL");
      return;
    }
    this.notifications.set(notification.key ?? notification.work.key, notification);
  }

  private async notify(notification: Notification): Promise<void> {
    const work = notification.work;
    if (!this.current(work)) return;
    const message = work.message;
    // Roles may change while Jev is answering; never reuse the discovery list for notification.
    let admins: readonly Admin[] = [];
    if (!notification.mark) {
      const members = await this.fetchAdmins(work);
      if (!members) return;
      if (message.senderId === members.ownMemberId) return;
      admins = members.admins;
    }
    const alerts = notification.build(admins);
    let sent = 0;
    for (const alert of alerts) {
      const sentFrame = await this.paced(work, this.sendQuotas, () => this.api.request("message:send", { chatId: message.channelId, ...alert }, "sent"));
      if (!sentFrame || !this.current(work)) return;
      sent += alert.mentions.length;
      this.emit("alert", { ...notification.event, mentioned: sent, total: admins.length });
    }
  }

  private async fetchAdmins(work: Work) {
    const frame = await this.paced(work, this.adminQuotas, () => this.api.request("chat:admins:get", { chatId: work.message.channelId }, "chat:admins"));
    if (!frame || !this.current(work)) return;
    const members = parseAdmins(frame, work.message.channelId);
    this.ownMembers.set(work.message.channelId, members.ownMemberId);
    return members;
  }

  private async fetchOwnMember(work: Work): Promise<void> {
    const chatId = work.message.channelId;
    const frame = await this.paced(work, this.membershipQuotas, () => this.api.request("chat:membership:get", { chatId }, "chat:membership"));
    if (!frame || !this.current(work)) return;
    this.ownMembers.set(chatId, parseMembership(frame, chatId));
  }
}

/** Client-side mirror of one upstream sliding-window limit, on the monotonic clock. */
class Quota {
  private readonly events: number[] = [];

  constructor(private readonly max: number, private readonly windowMs: number) {}

  /** Milliseconds until one more request fits; 0 when it fits now. */
  delay(now: number): number {
    while (this.events.length > 0 && now - this.events[0]! >= this.windowMs) this.events.shift();
    return this.events.length < this.max ? 0 : this.events[this.events.length - this.max]! + this.windowMs - now;
  }

  take(now: number): void {
    this.events.push(now);
  }
}
