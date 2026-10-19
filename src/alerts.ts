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

export function buildAlerts(
  message: Pick<Message, 'messageId'>,
  analysis: ScamAnalysis,
  admins: readonly Admin[],
): Array<{ text: string; mentions: Mention[]; replyTo: string }> {
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

  // Formatting never participates in the guard's unrounded threshold comparison.
  const probability = percentFormat.format(analysis.probability * 100);
  const label = tactic && Object.hasOwn(tacticLabels, tactic.kind) ? tacticLabels[tactic.kind] : '未能辨識的詐騙手法';
  const tacticText = tactic
    ? `${label}（手法信心度 ${percentFormat.format(tactic.confidence * 100)}%）`
    : '未提供詐騙手法及信心度';
  const sourceId = message.messageId.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, ' ');
  const header = `疑似詐騙提醒\n訊息 ID：${sourceId}\n詐騙機率：${probability}%\n手法：${tacticText}\n此為模型估計，並非事實判定，請管理員查證。\n`;
  const alerts: Array<{ text: string; mentions: Mention[]; replyTo: string }> = [];
  for (let offset = 0; offset < unique.length; offset += 20) {
    let text = header;
    const mentions: Mention[] = [];
    for (let index = offset; index < Math.min(offset + 20, unique.length); index++) {
      const admin = unique[index]!;
      let name = '';
      let space = false;
      // Delay spaces until another visible character preserves trim-before-truncate.
      // Stop at the UTF-16 bound without cleaning or copying the unused suffix.
      for (const character of admin.displayName) {
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
      if (name === '') name = '管理員';
      if (mentions.length > 0) text += ' ';
      const start = text.length;
      text += `@${name}`;
      mentions.push({ userId: admin.userId, start, end: text.length });
    }
    // Fixed header and bounded names keep batches comfortably below the LINE limit.
    if (text.length > 8000) throw new Error('Administrator alert exceeds the message size limit.');
    alerts.push({ text, mentions, replyTo: message.messageId });
  }
  return alerts;
}
