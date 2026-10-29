import test from 'node:test';
import assert from 'node:assert/strict';
import { isMessage, parseJoin } from '../dist/protocol.js';

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

test('join pictures accept only the LINE CDN and the matching member route, retaining hash preview priority', () => {
  const member = { userId: 'p' + 'a'.repeat(32), displayName: '成員' };
  const parse = extra => parseJoin({ type: 'chat:member-joined', chatId: message.channelId, member: { ...member, ...extra } });
  const memberPath = `r/g2/member/${member.userId}`;
  assert.equal(parse({ pictureUrl: `https://obs.line-scdn.net/${memberPath}` }).picturePath, memberPath);
  assert.equal(parse({ pictureUrl: 'https://obs.line-scdn.net/0hash' }).picturePath, '0hash/preview');
  assert.equal(parse({ pictureUrl: 'https://obs.line-scdn.net/0hash/preview' }).picturePath, '0hash/preview');
  assert.equal(parse({ pictureId: 'avatar-o-0hash', pictureUrl: `https://obs.line-scdn.net/${memberPath}` }).picturePath, '0hash/preview');
  for (const pictureUrl of [
    `http://obs.line-scdn.net/${memberPath}`, `https://evil.test/${memberPath}`,
    `https://obs.line-scdn.net.evil.test/${memberPath}`, `https://user@obs.line-scdn.net/${memberPath}`,
    `https://obs.line-scdn.net/${memberPath}?token=x`, `https://obs.line-scdn.net/${memberPath}#fragment`,
    `https://obs.line-scdn.net/${memberPath}/../other`,
    'https://obs.line-scdn.net/r/g2/member/p' + 'b'.repeat(32),
  ]) assert.equal(parse({ pictureUrl }).picturePath, undefined);
});
