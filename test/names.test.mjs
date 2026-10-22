import test from 'node:test';
import assert from 'node:assert/strict';
import { isAdminLikeName } from '../dist/names.js';

test('admin-like names are found through spacing, symbols, width, case and look-alike characters', () => {
  for (const name of ['管管', '社群管理員', '群管小幫手', '副管 Amy', '版主', '板主', '群主', '管 理', '管_理✨員', '群\u200b管', '菅理員', '官方管里', 'ＡＤＭＩＮ', 'Admin_Amy', 'moderator', '官方小幫手', '小 助 手', '社群小編', '小帮手', '小编Amy']) {
    assert.equal(isAdminLikeName(name), true, name);
  }
});

test('spacing cannot split a Latin admin word either', () => {
  assert.equal(isAdminLikeName('Ad Min'), true);
});

test('ordinary names, including single shared characters, are not flagged', () => {
  for (const name of ['', '小明', '管小姐', '理查', '主任', '群群', 'Madison', '幫手', '助手', '小明編劇'.slice(2)]) {
    assert.equal(isAdminLikeName(name), false, name);
  }
});
