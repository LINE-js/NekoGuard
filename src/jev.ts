import type { ScamAnalysis } from "./protocol.js";
import { randomUUID } from "node:crypto";

const ENDPOINT = "https://api.typesafe.ai/v1/systemone";
const MAX_PICTURE_BYTES = 2 * 1024 * 1024;
const MAX_BODY_CHARS = 64 * 1024;

const CROWN_QUESTION = {
  type: "noul",
  instructions: "Does `avatar` (a chat member's profile picture) show a crown?",
  criteria: {
    true: "Any crown, tiara or crown symbol, emoji, icon or badge appears anywhere in the picture, including one drawn to look like a chat administrator's crown badge.",
    false: "No crown, tiara or crown-like symbol appears in the picture.",
  },
} as const;

export interface CrownCheckerOptions {
  /** TypeSafe API key; only ever sent as the bearer header to TypeSafe. */
  token: string;
  model: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Crown probability of an OpenChat profile picture, for LINE.js backends that announce joins
 * but cannot judge pictures themselves. The picture comes from LINE's public OpenChat CDN.
 * Errors carry codes only: never the picture, response body or key.
 */
export class CrownChecker {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly options: CrownCheckerOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  /** `pictureHash` is the obs hash LINE.js reported; null when LINE no longer has the picture. */
  async check(pictureHash: string): Promise<number | null> {
    const picture = await this.fetchPicture(pictureHash);
    if (!picture) return null;
    const reference = randomUUID();
    const response = await this.fetchImpl(ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.options.token}`,
        "Content-Type": "application/json",
        // TypeSafe's experimental image tier must be opted into per request.
        "TypeSafe-Danger-Zone-Images": "true",
      },
      body: JSON.stringify({
        model: this.options.model,
        state: { avatar: reference },
        assets: { [reference]: { type: "image", format: picture.format, data_base64: picture.bytes.toString("base64") } },
        questions: { crown: CROWN_QUESTION },
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
      // The key must never follow a redirect to some other host.
      redirect: "error",
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new Error("CROWN_CHECK_FAILED");
    }
    const body = await readLimited(response, MAX_BODY_CHARS);
    let probability: unknown;
    try {
      probability = (JSON.parse(body.toString("utf8")) as { answers?: { crown?: { noul?: unknown } } } | null)?.answers?.crown?.noul;
    } catch {
      throw new Error("CROWN_CHECK_FAILED");
    }
    if (typeof probability !== "number" || !Number.isFinite(probability) || probability < 0 || probability > 1) {
      throw new Error("CROWN_CHECK_FAILED");
    }
    return probability;
  }

  private async fetchPicture(hash: string): Promise<{ format: "png" | "jpg"; bytes: Buffer } | undefined> {
    // The small preview is enough to see a crown and keeps the paid image small.
    const response = await this.fetchImpl(`https://obs.line-scdn.net/${hash}/preview`, {
      signal: AbortSignal.timeout(this.timeoutMs), redirect: "error",
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 404 || response.status === 403) return undefined;
      throw new Error("CROWN_PICTURE_FAILED");
    }
    const bytes = await readLimited(response, MAX_PICTURE_BYTES);
    // TypeSafe reads only PNG and JPEG.
    if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { format: "png", bytes };
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return { format: "jpg", bytes };
    throw new Error("CROWN_PICTURE_UNSUPPORTED");
  }
}

async function readLimited(response: Response, limit: number): Promise<Buffer> {
  if (Number(response.headers.get("content-length") ?? 0) > limit) {
    await response.body?.cancel().catch(() => {});
    throw new Error("CROWN_RESPONSE_TOO_LARGE");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  if (response.body) {
    for await (const chunk of response.body) {
      size += chunk.byteLength;
      if (size > limit) throw new Error("CROWN_RESPONSE_TOO_LARGE");
      chunks.push(Buffer.from(chunk));
    }
  }
  return Buffer.concat(chunks, size);
}

// TypeSafe documents English as the language Jev answers most accurately in, so the questions are
// English; the message itself is sent as it is.
const TACTICS = {
  investment: "Investment, stock tips, crypto or get-rich-quick schemes, invitations to investment groups",
  impersonation: "Pretending to be a government agency, police, prosecutor, bank, telecom, delivery company or customer service",
  phishing: "A link or request to log in, verify an account, or hand over passwords, verification codes or card numbers",
  shopping: "Online shopping or payment problems, cancelling installments, fake sellers or buyers",
  friend: "Pretending to be a friend or relative who urgently needs money, or a hijacked account asking for money",
  romance: "Online dating or romance that leads to requests for money",
  job: "Part-time jobs, easy work for high pay, or renting out bank accounts, cards or phone numbers",
  prize: "Lottery wins, prizes, rewards or free gifts that require a fee or personal data",
  loan: "Loans, debt consolidation or credit offers that require fees up front",
  other: "Any other kind of scam",
} as const;

const SCAM_QUESTIONS = {
  scam: {
    type: "noul",
    instructions: "Is this chat message a scam or fraud attempt?",
    criteria: {
      true: "It tries to deceive the reader into giving money, account credentials, verification codes or personal data, or into clicking, installing or joining something under false pretences.",
      false: "An ordinary, honest message with no deceptive intent.",
    },
  },
  tactic: {
    type: "choice",
    instructions: "If this message were a scam, which kind of scam would it most resemble?",
    criteria: TACTICS,
  },
} as const;

function unit(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

/**
 * Scam probability of one message, for LINE.js backends without `scam:check` (it moved here).
 * Only the message text leaves this machine. Errors carry codes only: never the text, body or key.
 */
export class ScamChecker {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly options: CrownCheckerOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  async check(text: string): Promise<ScamAnalysis> {
    let response: Response;
    try {
      response = await this.fetchImpl(ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.options.token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model: this.options.model, state: text, questions: SCAM_QUESTIONS }),
        signal: AbortSignal.timeout(this.timeoutMs),
        // The key must never follow a redirect to some other host.
        redirect: "error",
      });
    } catch {
      throw new Error("SCAM_CHECK_FAILED");
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new Error("SCAM_CHECK_FAILED");
    }
    let answers: unknown;
    try {
      const body = await readLimited(response, MAX_BODY_CHARS);
      answers = (JSON.parse(body.toString("utf8")) as { answers?: unknown } | null)?.answers;
    } catch {
      throw new Error("SCAM_CHECK_FAILED");
    }
    if (!answers || typeof answers !== "object") throw new Error("SCAM_CHECK_FAILED");
    const { scam, tactic } = answers as { scam?: { noul?: unknown }; tactic?: { choice?: unknown; confidence?: unknown } };
    const probability = scam?.noul;
    if (!unit(probability)) throw new Error("SCAM_CHECK_FAILED");
    // An unreadable tactic is left out; the probability alone still decides.
    const kind = tactic?.choice;
    const confidence = tactic?.confidence;
    return typeof kind === "string" && Object.hasOwn(TACTICS, kind) && unit(confidence)
      ? { probability, tactic: { kind, confidence } }
      : { probability };
  }
}
