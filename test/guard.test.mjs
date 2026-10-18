import test from 'node:test';
import assert from 'node:assert/strict';
import { ScamGuard } from '../dist/guard.js';
import { ApiError } from '../dist/client.js';

const chatId = 'm' + 'a'.repeat(32);
const ownId = 'p' + 'b'.repeat(32);
const userId = 'u' + 'b'.repeat(32);
const senderId = 'p' + 'c'.repeat(32);
const admin = { userId: 'p' + 'd'.repeat(32), displayName: '管理員', role: 'admin' };
const message = (id, extra = {}) => ({ messageId: String(id), channelId: chatId, channelKind: 'square', senderId, senderName: 'Sender', text: '投資邀請', contentType: 'NONE', createdAt: 1, ...extra });

function harness(options = {}) {
  const calls = [];
  const sends = [];
  const notices = [];
  let admins = [admin];
  const api = { async request(type, fields) {
    calls.push({ type, ...fields });
    if (type === 'chat:admins:get') return { type: 'chat:admins', chatId, ownMemberId: ownId, admins };
    if (type === 'scam:check') {
      if (options.check) return options.check(fields);
      return { type: 'scam:result', ...fields, analysis: { probability: options.probability ?? 0.7, tactic: { kind: 'investment', confidence: 0.8 } } };
    }
    if (type === 'message:send') {
      sends.push(fields);
      if (options.send) return options.send(fields);
      return { type: 'sent', messageId: String(100 + sends.length) };
    }
    throw new Error('unexpected request');
  } };
  const guard = new ScamGuard(api, { thresholdPercent: options.threshold ?? 70, checkIntervalMs: 0, sendIntervalMs: 0, adminIntervalMs: 0 });
  guard.on('notice', code => notices.push(code));
  guard.on('fatal', code => notices.push(code));
  const ready = () => {
    guard.handle({ type: 'hello', protocol: 2, capabilities: ['chat:admins'] });
    guard.handle({ type: 'auth:ready', profile: { userId } });
    guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind: 'square' }] });
  };
  ready();
  return { guard, calls, sends, notices, ready, setAdmins(value) { admins = value; } };
}

test('70% inclusive threshold; below threshold does not notify; tactic confidence is not scam probability', async () => {
  for (const [probability, threshold, expected] of [[0.699999, 70, false], [0.7, 70, true], [0.8, 90, false], [0, 0, true], [1, 100, true]]) {
    const h = harness({ probability, threshold });
    h.guard.handle({ type: 'message', message: message(1) });
    await h.guard.whenIdle();
    assert.equal(h.sends.some(send => send.mentions.some(mention => mention.userId === admin.userId)), expected);
    if (expected) assert.equal(h.sends[0].replyTo, '1');
  }
});

test('excludes account and own OpenChat phone messages before any paid analysis, including first message', async () => {
  const h = harness();
  h.guard.handle({ type: 'message', message: message(1, { senderId: ownId }) });
  h.guard.handle({ type: 'message', message: message(2, { senderId: userId }) });
  await h.guard.whenIdle();
  assert.deepEqual(h.calls.filter(call => call.type === 'scam:check'), []);
  assert.deepEqual(h.sends, []);
  h.guard.handle({ type: 'message', message: message(3) });
  await h.guard.whenIdle();
  h.guard.handle({ type: 'message', message: message(101, { senderId: ownId, text: h.sends[0].text }) });
  await h.guard.whenIdle();
  assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['3']);
});

test('refreshes admin roles after analysis; mentions every current admin but no former admin', async () => {
  const gate = Promise.withResolvers();
  const h = harness({ check: () => gate.promise });
  h.guard.handle({ type: 'message', message: message(1) });
  await new Promise(resolve => setImmediate(resolve));
  const admins = Array.from({ length: 41 }, (_, i) => ({ userId: 'p' + String(i).padStart(32, '0'), displayName: `成員${i}`, role: i === 0 ? 'admin' : 'coAdmin' }));
  h.setAdmins(admins);
  gate.resolve({ type: 'scam:result', chatId, messageId: '1', analysis: { probability: 0.9 } });
  await h.guard.whenIdle();
  assert.deepEqual(h.sends.flatMap(send => send.mentions.map(mention => mention.userId)), admins.map(admin => admin.userId));
  assert(h.sends.every(send => send.mentions.length <= 20));
});

test('deduplicates events but evaluates an edited text; a stale in-flight result cannot warn', async () => {
  const gate = Promise.withResolvers();
  let first = true;
  const h = harness({ check: async fields => {
    if (first) { first = false; return gate.promise; }
    return { type: 'scam:result', ...fields, analysis: { probability: 0.1 } };
  } });
  h.guard.handle({ type: 'message', message: message(1) });
  await new Promise(resolve => setImmediate(resolve));
  h.guard.handle({ type: 'message', message: message(1) });
  h.guard.handle({ type: 'message:edit', message: message(1, { text: '普通問候', editedAt: 2 }) });
  gate.resolve({ type: 'scam:result', chatId, messageId: '1', analysis: { probability: 0.99 } });
  await h.guard.whenIdle();
  assert.deepEqual(h.sends, []);
  assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 2);
});

test('unsend or account transition invalidates an in-flight analysis', async () => {
  for (const event of [{ type: 'message:unsend', chatId, messageId: '1' }, { type: 'auth:state', state: 'idle' }]) {
    const gate = Promise.withResolvers();
    const h = harness({ check: () => gate.promise });
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    h.guard.handle(event);
    gate.resolve({ type: 'scam:result', chatId, messageId: '1', analysis: { probability: 0.99 } });
    await h.guard.whenIdle();
    assert.deepEqual(h.sends, []);
  }
});

test('ignores historical, system, undecryptable, withdrawn, non-text and unscoped messages', async () => {
  const h = harness();
  h.guard.handle({ type: 'messages', chatId, messages: [message(1)] });
  for (const extra of [{ contentType: 'CHATEVENT' }, { contentType: 'IMAGE' }, { decryptFailed: true }, { unsent: true }, { channelId: 'm' + 'e'.repeat(32) }]) {
    h.guard.handle({ type: 'message', message: message(2, extra) });
  }
  await h.guard.whenIdle();
  assert.deepEqual(h.calls, []);
});

test('does not fabricate results on failure or retry an ambiguous send', async () => {
  for (const check of [async () => { throw new ApiError('RATE_LIMITED'); }, async fields => ({ type: 'scam:result', ...fields, analysis: { probability: NaN } })]) {
    const h = harness({ check });
    h.guard.handle({ type: 'message', message: message(1) });
    await h.guard.whenIdle();
    assert.deepEqual(h.sends, []);
    assert.notEqual(h.notices.at(-1), 'MONITORING_READY');
  }
  const h = harness({ send: async () => { throw new ApiError('REQUEST_TIMEOUT'); } });
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  assert.equal(h.sends.length, 1);
  assert.equal(h.notices.at(-1), 'REQUEST_TIMEOUT');
});

test('refuses unpatched backend instead of pretending all administrators were found', async () => {
  const h = harness();
  h.guard.handle({ type: 'hello', protocol: 2 });
  h.guard.handle({ type: 'auth:ready', profile: { userId } });
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  assert(h.notices.includes('LINEJS_ADMIN_EXTENSION_REQUIRED'));
  assert.deepEqual(h.calls, []);
});

test('a slow Jev result does not block another message from warning', async () => {
  const slow = Promise.withResolvers();
  const h = harness({ check: fields => fields.messageId === '1' ? slow.promise
    : { type: 'scam:result', ...fields, analysis: { probability: 0.9 } } });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    h.guard.handle({ type: 'message', message: message(2) });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.sends.map(send => send.replyTo), ['2']);
  } finally {
    slow.resolve({ type: 'scam:result', chatId, messageId: '1', analysis: { probability: 0.1 } });
    await h.guard.whenIdle();
  }
});

test('bounds outstanding analyses and drains remaining messages without loss', async () => {
  const release = Promise.withResolvers();
  let active = 0;
  let peak = 0;
  const checked = [];
  const h = harness({ check: async fields => {
    active++;
    peak = Math.max(peak, active);
    checked.push(fields.messageId);
    await release.promise;
    active--;
    return { type: 'scam:result', ...fields, analysis: { probability: 0.1 } };
  } });
  try {
    for (let i = 1; i <= 12; i++) h.guard.handle({ type: 'message', message: message(i) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(active, 4);
  } finally {
    release.resolve();
    await h.guard.whenIdle();
  }
  assert.equal(peak, 4);
  assert.deepEqual(checked.slice().sort(), Array.from({ length: 12 }, (_, i) => String(i + 1)).sort());
});

test('analysis continues during a blocked notification; account change cancels queued notifications', async () => {
  const sent = Promise.withResolvers();
  const h = harness({ send: () => sent.promise });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    h.guard.handle({ type: 'message', message: message(2) });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['1', '2']);
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
    h.guard.handle({ type: 'auth:state', state: 'idle' });
  } finally {
    sent.resolve({ type: 'sent', messageId: '101' });
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
});
