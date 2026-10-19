export interface Message {
  messageId: string;
  channelId: string;
  channelKind: "user" | "group" | "room" | "square";
  senderId: string;
  senderName: string;
  text?: string;
  contentType: string;
  createdAt: number;
  editedAt?: number;
  unsent?: boolean;
  decryptFailed?: boolean;
}

export interface ScamAnalysis {
  probability: number;
  tactic?: { kind: string; confidence: number };
}

export interface Admin {
  userId: string;
  displayName: string;
  role: "admin" | "coAdmin";
}

export interface Mention {
  userId: string;
  start: number;
  end: number;
}

export type Frame = { type: string; requestId?: string } & Record<string, unknown>;

export interface Api {
  request(type: string, fields: Record<string, unknown>, responseType: string): Promise<Frame>;
}

export function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isMessage(value: unknown): value is Message {
  if (!record(value)) return false;
  return typeof value.messageId === "string" && /^\d{1,24}$/.test(value.messageId)
    && typeof value.channelId === "string" && /^[ucrsm][A-Za-z0-9]{10,64}$/.test(value.channelId)
    && typeof value.senderId === "string" && typeof value.senderName === "string"
    && (value.channelKind === "user" || value.channelKind === "group"
      || value.channelKind === "room" || value.channelKind === "square")
    && typeof value.contentType === "string" && typeof value.createdAt === "number"
    && (value.text === undefined || typeof value.text === "string");
}

export function parseAdmins(frame: Frame, chatId: string): { admins: Admin[]; ownMemberId: string } {
  if (frame.chatId !== chatId || typeof frame.ownMemberId !== "string"
    || !/^p[A-Za-z0-9]{10,64}$/.test(frame.ownMemberId) || !Array.isArray(frame.admins)) {
    throw new Error("INVALID_ADMIN_RESPONSE");
  }
  const admins: Admin[] = [];
  for (const entry of frame.admins as unknown[]) {
    if (!record(entry) || typeof entry.userId !== "string" || !/^p[A-Za-z0-9]{10,64}$/.test(entry.userId)
      || typeof entry.displayName !== "string" || (entry.role !== "admin" && entry.role !== "coAdmin")) {
      throw new Error("INVALID_ADMIN_RESPONSE");
    }
    admins.push({ userId: entry.userId, displayName: entry.displayName, role: entry.role });
  }
  return { admins, ownMemberId: frame.ownMemberId };
}

export function parseAnalysis(frame: Frame, message: Pick<Message, "channelId" | "messageId">): ScamAnalysis {
  const analysis = frame.analysis;
  if (frame.chatId !== message.channelId || frame.messageId !== message.messageId
    || !record(analysis) || !unit(analysis.probability)) throw new Error("INVALID_SCAM_RESPONSE");
  if (analysis.tactic === undefined) return { probability: analysis.probability };
  const tactic = analysis.tactic;
  if (!record(tactic) || typeof tactic.kind !== "string" || !unit(tactic.confidence)) {
    throw new Error("INVALID_SCAM_RESPONSE");
  }
  return { probability: analysis.probability, tactic: { kind: tactic.kind, confidence: tactic.confidence } };
}

function unit(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}
