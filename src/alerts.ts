import type { Admin, Mention, Message, ScamAnalysis } from './protocol.js';

const tacticLabels: Readonly<Record<string, string>> = {
  investment: '投資詐騙',
  impersonation: '冒名詐騙',
  phishing: '釣魚詐騙',
  shopping: '購物詐騙',
  friend: '假冒親友',
  romance: '感情詐騙',
  job: '求職詐騙',
  prize: '中獎詐騙',
  loan: '貸款詐騙',
  other: '其他詐騙手法',
};

const percentFormat = new Intl.NumberFormat('zh-TW', {
  maximumFractionDigits: 12, useGrouping: false,
});
const nameSeparator = /[\s\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069]/u;

export interface Alert {
  text: string;
  mentions: Mention[];
  replyTo?: string;
}

/** `basis` says what the mention rests on: the detector alone, a confirmed intent, or a failed review. */
export type AlertBasis = 'detector' | 'intent' | 'unreviewed';

const basisText: Readonly<Record<AlertBasis, string>> = {
  detector: '此為模型估計，並非事實判定，請管理員查證。',
  intent: '發言意圖經分析判定為詐騙；此為模型估計，並非事實判定，請管理員查證。',
  unreviewed: '發言意圖分析失敗，依詐騙機率通知；此為模型估計，並非事實判定，請管理員查證。',
};

export function buildAlerts(
  message: Pick<Message, 'messageId'>,
  analysis: ScamAnalysis,
  admins: readonly Admin[],
  basis: AlertBasis = 'detector',
): Alert[] {
  validate(message, analysis);
  const header = `疑似詐騙提醒\n訊息 ID：${stripControls(message.messageId)}\n${describe(analysis)}\n${basisText[basis]}\n`;
  return mentionAdmins(header, admins, message.messageId);
}

function validate(message: Pick<Message, 'messageId'>, analysis: ScamAnalysis): void {
  if (!analysis || typeof analysis.probability !== 'number' || !Number.isFinite(analysis.probability) || analysis.probability < 0 || analysis.probability > 1) {
    throw new Error('Invalid scam probability; expected a finite value between 0 and 1.');
  }
  const tactic = analysis.tactic;
  if (tactic !== undefined && (!tactic || typeof tactic.kind !== 'string' || typeof tactic.confidence !== 'number' || !Number.isFinite(tactic.confidence) || tactic.confidence < 0 || tactic.confidence > 1)) {
    throw new Error('Invalid scam tactic analysis.');
  }
  if (typeof message.messageId !== 'string' || message.messageId.trim() === '' || message.messageId.length > 512) {
    throw new Error('Invalid source message ID.');
  }
}

/** Stage one: a reply that marks the message for everyone, without mentioning anyone. */
export function buildMark(message: Pick<Message, 'messageId'>, analysis: ScamAnalysis): Alert {
  validate(message, analysis);
  return {
    text: `疑似詐騙預警\n${describe(analysis)}\n發言意圖分析中；請勿點擊連結、匯款或提供個人資料。此為模型估計，並非事實判定。`,
    mentions: [],
    replyTo: message.messageId,
  };
}

/** Only a bounded author label is retained; the post itself is never included. */
export function buildNoteSubject(displayName: string): string {
  return `「${cleanName(displayName, '（未提供名稱）')}」在記事本的文章`;
}

export function buildNoteMark(subject: string, analysis: ScamAnalysis): Alert {
  return {
    text: `疑似詐騙預警\n${subject}疑似詐騙。\n${describe(analysis)}\n發文意圖分析中；請勿點擊連結、匯款或提供個人資料。此為模型估計，並非事實判定。`,
    mentions: [],
  };
}

/** OpenChat mentions current admins; ordinary groups have no administrator API. */
export function buildNoteAlerts(subject: string, analysis: ScamAnalysis, admins?: readonly Admin[]): Alert[] {
  const header = `疑似詐騙提醒\n${subject}經意圖分析判定為詐騙。\n${describe(analysis)}\n此為模型估計，並非事實判定，請${admins ? '管理員' : '群組成員'}查證。\n`;
  return admins ? mentionAdmins(header, admins) : [{ text: header.trimEnd(), mentions: [] }];
}

function describe(analysis: ScamAnalysis): string {
  const tactic = analysis.tactic;
  // Formatting never participates in the guard's unrounded threshold comparison.
  const probability = percentFormat.format(analysis.probability * 100);
  const label = tactic && Object.hasOwn(tacticLabels, tactic.kind) ? tacticLabels[tactic.kind] : '未能辨識的詐騙手法';
  const tacticText = tactic
    ? `${label}（手法信心度 ${percentFormat.format(tactic.confidence * 100)}%）`
    : '未提供詐騙手法及信心度';
  return `詐騙機率：${probability}%\n手法：${tacticText}`;
}

export interface JoinFindings {
  /** Jev's crown probability; undefined when it could not be judged, null when the member has no picture. */
  crown: number | null | undefined;
  crownHit: boolean;
  nameHit: boolean;
}

export function buildJoinAlerts(
  member: { userId: string; displayName: string },
  findings: JoinFindings,
  admins: readonly Admin[],
): Alert[] {
  if (!findings.crownHit && !findings.nameHit) throw new Error('A join alert needs at least one finding.');
  // No picture means no crown: 0%. Only an unjudged picture has no number to show.
  const crown = findings.crown === undefined ? '未能判定' : `${percentFormat.format((findings.crown ?? 0) * 100)}%`;
  // Plain text, never a mention: the newcomer is untrusted and has not spoken in the chat.
  const header = `疑似冒充管理員提醒\n新成員：${cleanName(member.displayName, '（未提供名稱）')}\n成員 ID：${stripControls(member.userId)}\n假皇冠機率：${crown}\n名稱含管理員相關字詞：${findings.nameHit ? '是' : '否'}\n此為自動判定，並非事實認定，請管理員查證。\n`;
  return mentionAdmins(header, admins);
}

function stripControls(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, ' ');
}

/** Collapse separators and bound to 80 UTF-16 units without cleaning or copying the unused suffix. */
function cleanName(displayName: string, fallback: string): string {
  let name = '';
  let space = false;
  // Delay spaces until another visible character preserves trim-before-truncate.
  for (const character of displayName) {
    if (name.length === 80) break;
    if (nameSeparator.test(character)) {
      space = name.length > 0;
      continue;
    }
    if (space) {
      name += ' ';
      space = false;
    }
    if (name.length + character.length > 80) break;
    name += character;
  }
  return name === '' ? fallback : name;
}

function mentionAdmins(header: string, admins: readonly Admin[], replyTo?: string): Alert[] {
  const unique: Admin[] = [];
  const seen = new Set<string>();
  for (const admin of admins) {
    if (typeof admin.userId !== 'string' || admin.userId.trim() === '' || typeof admin.displayName !== 'string') {
      throw new Error('Invalid administrator metadata.');
    }
    if (!seen.has(admin.userId)) {
      seen.add(admin.userId);
      unique.push(admin);
    }
  }
  if (unique.length === 0) throw new Error('Cannot create an alert without administrators.');
  const alerts: Alert[] = [];
  for (let offset = 0; offset < unique.length; offset += 20) {
    let text = header;
    const mentions: Mention[] = [];
    for (let index = offset; index < Math.min(offset + 20, unique.length); index++) {
      const admin = unique[index]!;
      const name = cleanName(admin.displayName, '管理員');
      if (mentions.length > 0) text += ' ';
      const start = text.length;
      text += `@${name}`;
      mentions.push({ userId: admin.userId, start, end: text.length });
    }
    // Fixed header and bounded names keep batches comfortably below the LINE limit.
    if (text.length > 8000) throw new Error('Administrator alert exceeds the message size limit.');
    alerts.push(replyTo === undefined ? { text, mentions } : { text, mentions, replyTo });
  }
  return alerts;
}
