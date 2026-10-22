// Words an impostor uses to pass as a chat administrator. Matched after folding width, case and
// script variants and dropping everything that is not a letter or digit, so spacing, symbols,
// emoji or zero-width characters between the characters ("管 理", "管_管", "群．管") cannot hide them.
const WORDS = ['管管', '管理', '群管', '副管', '版主', '板主', '群主', '小幫手', '小帮手', '小助手', '小編', '小编', 'admin', 'moderator'];

// Look-alike and variant characters folded to the forms in WORDS.
const FOLD: Readonly<Record<string, string>> = { 菅: '管', 筦: '管', 里: '理', 羣: '群' };

export function isAdminLikeName(displayName: string): boolean {
  let folded = '';
  for (const character of displayName.normalize('NFKC').toLowerCase()) {
    if (/[\p{L}\p{N}]/u.test(character)) folded += FOLD[character] ?? character;
  }
  return WORDS.some(word => folded.includes(word));
}
