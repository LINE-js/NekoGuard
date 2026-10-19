import test from 'node:test';
import assert from 'node:assert/strict';
import { isMessage } from '../dist/protocol.js';

const message = {
  messageId: '1', channelId: 'm' + 'a'.repeat(32),
  senderId: 'p' + 'b'.repeat(32), senderName: 'Sender',
  contentType: 'NONE', createdAt: 1, text: 'hello',
};

test('message kinds require exact protocol strings without coercing JSON values', () => {
  for (const channelKind of ['user', 'group', 'room', 'square']) {
    assert.equal(isMessage({ ...message, channelKind }), true);
  }
  for (const channelKind of [
    ['square'], { toString: 'square' }, { toString: null, valueOf: null },
    {}, null, undefined, 0, true, 'Square', 'square ', 'unknown',
  ]) {
    assert.equal(isMessage({ ...message, channelKind }), false);
  }
});
