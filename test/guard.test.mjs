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
    options.onRequest?.(type, fields);
    if (type === 'chat:admins:get') {
      if (options.admins) return options.admins(fields);
      return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: ownId, admins };
    }
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
  const guard = new ScamGuard(api, { thresholdPercent: options.threshold ?? 70, checkIntervalMs: 0, sendIntervalMs: 0, adminIntervalMs: 0, ...options.intervals });
  guard.on('notice', code => notices.push(code));
  guard.on('fatal', code => notices.push(code));
  const ready = () => {
    guard.handle({ type: 'hello', protocol: 2, capabilities: ['chat:admins'] });
    guard.handle({ type: 'auth:ready', profile: { userId } });
    guard.handle({ type: 'channels', channels: (options.chats ?? [chatId]).map(channelId => ({ channelId, kind: 'square' })) });
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
    for (let id = 2; id <= 12; id++) h.guard.handle({ type: 'message', message: message(id) });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId),
      Array.from({ length: 12 }, (_, i) => String(i + 1)));
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
    h.guard.handle({ type: 'auth:state', state: 'idle' });
  } finally {
    sent.resolve({ type: 'sent', messageId: '101' });
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
});

test('a blocked chat keeps its mention grants without delaying discovery or warnings in another chat', async () => {
  const otherChat = 'm' + 'e'.repeat(32);
  const sent = Promise.withResolvers();
  const h = harness({
    chats: [chatId, otherChat],
    send: fields => fields.chatId === chatId && fields.replyTo === '1' ? sent.promise : { type: 'sent' },
  });
  h.setAdmins(Array.from({ length: 21 }, (_, i) => ({ ...admin, userId: 'p' + String(i).padStart(32, '0') })));
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    h.guard.handle({ type: 'message', message: message(2) });
    h.guard.handle({ type: 'message', message: message(3, { channelId: otherChat }) });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['1', '2', '3']);
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1', '3', '3']);
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get' && call.chatId === chatId).length, 2);
  } finally {
    sent.resolve({ type: 'sent' });
    await h.guard.whenIdle();
  }
  const ownCalls = h.calls.filter(call => call.chatId === chatId);
  const lastFirstBatch = ownCalls.findLastIndex(call => call.type === 'message:send' && call.replyTo === '1');
  const secondLookup = ownCalls.findLastIndex(call => call.type === 'chat:admins:get');
  assert(lastFirstBatch < secondLookup);
  assert.deepEqual(h.sends.filter(send => send.chatId === chatId).map(send => send.replyTo), ['1', '1', '2', '2']);
});

test('notification concurrency is bounded independently of analysis and drains all chats', async () => {
  const chats = Array.from({ length: 6 }, (_, i) => 'm' + String(i).padStart(32, '0'));
  const release = Promise.withResolvers();
  let active = 0;
  let peak = 0;
  const h = harness({ chats, send: async () => {
    active++;
    peak = Math.max(peak, active);
    await release.promise;
    active--;
    return { type: 'sent' };
  } });
  try {
    chats.forEach((channelId, i) => h.guard.handle({ type: 'message', message: message(i + 1, { channelId }) }));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(active, 4);
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['1', '2', '3', '4', '5', '6']);
  } finally {
    release.resolve();
    await h.guard.whenIdle();
  }
  assert.equal(peak, 4);
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1', '2', '3', '4', '5', '6']);
});

test('notification backlog is bounded, reports overflow, and reclaims a withdrawn slot', async () => {
  const release = Promise.withResolvers();
  const h = harness({ send: () => release.promise });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    for (let id = 2; id <= 502; id++) {
      h.guard.handle({ type: 'message', message: message(id) });
      if (id % 100 === 0) await new Promise(resolve => setImmediate(resolve));
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 502);
    assert.deepEqual(h.notices.filter(code => code.endsWith('_QUEUE_FULL')), ['NOTIFICATION_QUEUE_FULL']);
    h.guard.handle({ type: 'message:unsend', chatId, messageId: '2' });
    h.guard.handle({ type: 'message', message: message(503) });
    await new Promise(resolve => setImmediate(resolve));
  } finally {
    release.resolve({ type: 'sent' });
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), [
    '1', ...Array.from({ length: 499 }, (_, i) => String(i + 3)), '503',
  ]);
});

test('edits and withdrawals invalidate notifications already waiting behind a send', async () => {
  const release = Promise.withResolvers();
  const h = harness({
    send: () => release.promise,
    check: fields => ({
      type: 'scam:result', ...fields,
      analysis: { probability: revised && fields.messageId === '2' ? 0.1 : 0.9 },
    }),
  });
  let revised = false;
  try {
    for (let id = 1; id <= 3; id++) h.guard.handle({ type: 'message', message: message(id) });
    await new Promise(resolve => setImmediate(resolve));
    revised = true;
    h.guard.handle({ type: 'message:edit', message: message(2, { text: '普通問候', editedAt: 2 }) });
    h.guard.handle({ type: 'message:unsend', chatId, messageId: '3' });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['1', '2', '3', '2']);
  } finally {
    release.resolve({ type: 'sent' });
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
});

test('failed notification releases its chat lane without retrying the ambiguous send', async () => {
  const h = harness({ send: fields => {
    if (fields.replyTo === '1') throw new ApiError('REQUEST_TIMEOUT');
    return { type: 'sent' };
  } });
  h.guard.handle({ type: 'message', message: message(1) });
  h.guard.handle({ type: 'message', message: message(2) });
  await h.guard.whenIdle();
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1', '2']);
  assert.deepEqual(h.notices.filter(code => code === 'REQUEST_TIMEOUT'), ['REQUEST_TIMEOUT']);
});

test('parallel chats share analysis, administrator and send pacing even when waiters wake together', async () => {
  const chats = Array.from({ length: 4 }, (_, i) => 'm' + String(i).padStart(32, '0'));
  const dispatches = [];
  const h = harness({
    chats,
    intervals: { checkIntervalMs: 10, adminIntervalMs: 15, sendIntervalMs: 40 },
    onRequest: type => dispatches.push({ type, at: Date.now() }),
  });
  try {
    chats.forEach((channelId, i) => h.guard.handle({ type: 'message', message: message(i + 1, { channelId }) }));
    await h.guard.whenIdle();
    assert.equal(h.sends.length, 4);
    for (const [type, minimum, count] of [['scam:check', 10, 4], ['chat:admins:get', 15, 8], ['message:send', 40, 4]]) {
      const times = dispatches.filter(call => call.type === type).map(call => call.at);
      assert.equal(times.length, count);
      for (let i = 1; i < times.length; i++) assert(times[i] - times[i - 1] >= minimum, type);
    }
  } finally {
    h.guard.stop();
    await h.guard.whenIdle();
  }
});

test('an edit invalidates an in-flight result even when the analysis queue is full', async () => {
  const release = Promise.withResolvers();
  const h = harness({ check: async fields => {
    if (Number(fields.messageId) <= 4) await release.promise;
    return { type: 'scam:result', ...fields, analysis: { probability: fields.messageId === '1' ? 0.99 : 0.1 } };
  } });
  try {
    for (let id = 1; id <= 4; id++) h.guard.handle({ type: 'message', message: message(id) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 4);
    for (let id = 5; id <= 504; id++) h.guard.handle({ type: 'message', message: message(id) });
    h.guard.handle({ type: 'message:edit', message: message(1, { text: '普通問候', editedAt: 2 }) });
    assert(h.notices.includes('ANALYSIS_QUEUE_FULL'));
  } finally {
    release.resolve();
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends, []);
  assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 504);
  assert.equal(h.calls.filter(call => call.type === 'scam:check' && call.messageId === '1').length, 1);
});

test('an edit invalidates a queued notification even when no new analysis can be admitted', async () => {
  const sent = Promise.withResolvers();
  const checked = Promise.withResolvers();
  const h = harness({
    send: () => sent.promise,
    check: async fields => {
      if (Number(fields.messageId) >= 3) await checked.promise;
      return { type: 'scam:result', ...fields, analysis: { probability: Number(fields.messageId) <= 2 ? 0.9 : 0.1 } };
    },
  });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    h.guard.handle({ type: 'message', message: message(2) });
    await new Promise(resolve => setImmediate(resolve));
    for (let id = 3; id <= 6; id++) h.guard.handle({ type: 'message', message: message(id) });
    await new Promise(resolve => setImmediate(resolve));
    for (let id = 7; id <= 506; id++) h.guard.handle({ type: 'message', message: message(id) });
    h.guard.handle({ type: 'message:edit', message: message(2, { text: '普通問候' }) });
    assert(h.notices.includes('ANALYSIS_QUEUE_FULL'));
  } finally {
    sent.resolve({ type: 'sent' });
    checked.resolve();
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
});

test('cold-chat followers share discovery without consuming other chats analysis workers', async () => {
  const otherChat = 'm' + 'e'.repeat(32);
  const discovery = Promise.withResolvers();
  const h = harness({
    chats: [chatId, otherChat],
    probability: 0.1,
    admins: async fields => {
      if (fields.chatId === chatId) await discovery.promise;
      return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: ownId, admins: [admin] };
    },
  });
  try {
    for (let id = 1; id <= 4; id++) h.guard.handle({ type: 'message', message: message(id) });
    h.guard.handle({ type: 'message', message: message(5, { channelId: otherChat }) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get' && call.chatId === chatId).length, 1);
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['5']);
  } finally {
    discovery.resolve();
    await h.guard.whenIdle();
  }
  assert.equal(h.calls.filter(call => call.type === 'chat:admins:get' && call.chatId === chatId).length, 1);
  assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId).sort(), ['1', '2', '3', '4', '5']);
});

test('invalidating a discovery leader does not abandon or duplicate its in-flight API request', async () => {
  const discovery = Promise.withResolvers();
  let first = true;
  const h = harness({
    probability: 0.1,
    admins: async fields => {
      if (first) { first = false; await discovery.promise; }
      return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: ownId, admins: [admin] };
    },
  });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    h.guard.handle({ type: 'message:unsend', chatId, messageId: '1' });
    h.guard.handle({ type: 'message', message: message(2) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get').length, 1);
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check'), []);
  } finally {
    discovery.resolve();
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['2']);
});

test('withdrawn analysis waiters release workers before the global rate-limit deadline', async () => {
  const otherChat = 'm' + 'e'.repeat(32);
  const h = harness({ chats: [chatId, otherChat], probability: 0.1, intervals: { checkIntervalMs: 60_000 } });
  try {
    h.guard.handle({ type: 'message', message: message(0) });
    await h.guard.whenIdle();
    for (let id = 1; id <= 4; id++) h.guard.handle({ type: 'message', message: message(id) });
    h.guard.handle({ type: 'message', message: message(5, { channelId: otherChat }) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get' && call.chatId === otherChat).length, 0);
    for (let id = 1; id <= 4; id++) h.guard.handle({ type: 'message:unsend', chatId, messageId: String(id) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get' && call.chatId === otherChat).length, 1);
    // Releasing workers must not release the shared analysis quota.
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check').map(call => call.messageId), ['0']);
  } finally {
    h.guard.stop();
    await h.guard.whenIdle();
  }
});

test('invalidated administrator and send waits release notification lanes immediately', async () => {
  for (const interval of ['adminIntervalMs', 'sendIntervalMs']) {
    const h = harness({ intervals: { [interval]: 60_000 } });
    try {
      h.guard.handle({ type: 'message', message: message(1) });
      await new Promise(resolve => setImmediate(resolve));
      if (interval === 'sendIntervalMs') {
        assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
        h.guard.handle({ type: 'message', message: message(2) });
        await new Promise(resolve => setImmediate(resolve));
      }
      const id = interval === 'sendIntervalMs' ? 2 : 1;
      // A non-text edit must invalidate the local wait just like an unsend.
      h.guard.handle({ type: 'message:edit', message: message(id, { contentType: 'IMAGE' }) });
      let idle = false;
      const drained = h.guard.whenIdle().then(() => { idle = true; });
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(idle, true, interval);
      await drained;
      assert.deepEqual(h.sends.map(send => send.replyTo), interval === 'sendIntervalMs' ? ['1'] : []);
    } finally {
      h.guard.stop();
      await h.guard.whenIdle();
    }
  }
});

test('removing and re-adding a chat invalidates its old analysis without affecting other chats', async () => {
  const otherChat = 'm' + 'e'.repeat(32);
  const release = Promise.withResolvers();
  const h = harness({
    chats: [chatId, otherChat],
    check: async fields => {
      await release.promise;
      return { type: 'scam:result', ...fields, analysis: { probability: 0.9 } };
    },
  });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    h.guard.handle({ type: 'message', message: message(2, { channelId: otherChat }) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 2);
    h.guard.handle({ type: 'channels', channels: [{ channelId: otherChat, kind: 'square' }] });
    h.guard.handle({ type: 'channels', channels: [chatId, otherChat].map(channelId => ({ channelId, kind: 'square' })) });
  } finally {
    release.resolve();
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['2']);
  // A fresh event, even with the same ID and text, is a new work version.
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  assert.deepEqual(h.sends.map(send => send.replyTo), ['2', '1']);
});

test('rejoining refreshes own identity and cannot restore identity from an old discovery response', async () => {
  const newOwnId = 'p' + 'f'.repeat(32);
  for (const pending of [false, true]) {
    const discovery = Promise.withResolvers();
    let lookups = 0;
    const h = harness({
      probability: 0.1,
      admins: async fields => {
        const first = ++lookups === 1;
        if (first && pending) await discovery.promise;
        return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: first ? ownId : newOwnId, admins: [admin] };
      },
    });
    try {
      h.guard.handle({ type: 'message', message: message(1, { senderId: ownId }) });
      await new Promise(resolve => setImmediate(resolve));
      h.guard.handle({ type: 'channels', channels: [] });
      h.guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind: 'square' }] });
      h.guard.handle({ type: 'message', message: message(2, { senderId: newOwnId }) });
    } finally {
      discovery.resolve();
      await h.guard.whenIdle();
    }
    assert.equal(lookups, 2);
    assert.deepEqual(h.calls.filter(call => call.type === 'scam:check'), []);
    assert.deepEqual(h.sends, []);
  }
});

test('chat removal cancels local waits permanently without resetting shared quotas', async () => {
  const otherChat = 'm' + 'e'.repeat(32);
  for (const interval of ['checkIntervalMs', 'adminIntervalMs', 'sendIntervalMs']) {
    const h = harness({ chats: [chatId, otherChat], intervals: { [interval]: 60_000 } });
    try {
      h.guard.handle({ type: 'message', message: message(1) });
      await new Promise(resolve => setImmediate(resolve));
      if (interval !== 'adminIntervalMs') {
        h.guard.handle({ type: 'message', message: message(2) });
        await new Promise(resolve => setImmediate(resolve));
      }
      const sendsBeforeRemoval = h.sends.map(send => send.replyTo);
      h.guard.handle({ type: 'channels', channels: [{ channelId: otherChat, kind: 'square' }] });
      h.guard.handle({ type: 'channels', channels: [chatId, otherChat].map(channelId => ({ channelId, kind: 'square' })) });
      let idle = false;
      const drained = h.guard.whenIdle().then(() => { idle = true; });
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(idle, true, interval);
      await drained;
      assert.deepEqual(h.sends.map(send => send.replyTo), sendsBeforeRemoval);
      const limitedType = { checkIntervalMs: 'scam:check', adminIntervalMs: 'chat:admins:get', sendIntervalMs: 'message:send' }[interval];
      const before = h.calls.filter(call => call.type === limitedType).length;
      h.guard.handle({ type: 'message', message: message(3, { channelId: otherChat }) });
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(h.calls.filter(call => call.type === limitedType).length, before, interval);
    } finally {
      h.guard.stop();
      await h.guard.whenIdle();
    }
  }
});

test('chat removal drops queued notifications and remaining batches but keeps tracking a sent request', async () => {
  const sent = Promise.withResolvers();
  const h = harness({ send: () => sent.promise });
  h.setAdmins(Array.from({ length: 21 }, (_, i) => ({ ...admin, userId: 'p' + String(i).padStart(32, '0') })));
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    h.guard.handle({ type: 'message', message: message(2) });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
    const lookups = h.calls.filter(call => call.type === 'chat:admins:get').length;
    h.guard.handle({ type: 'channels', channels: [] });
    h.guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind: 'square' }] });
    h.guard.handle({ type: 'message', message: message(3) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get').length, lookups);
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1']);
  } finally {
    sent.resolve({ type: 'sent' });
    await h.guard.whenIdle();
  }
  assert.deepEqual(h.sends.map(send => send.replyTo), ['1', '3', '3']);
});

test('a full notification backlog still admits free chat lanes without exceeding concurrency or queue bounds', async () => {
  const others = Array.from({ length: 4 }, (_, i) => 'm' + String(i).padStart(32, '0'));
  const release = Promise.withResolvers();
  let active = 0;
  let peak = 0;
  const h = harness({
    chats: [chatId, ...others],
    send: async () => {
      active++;
      peak = Math.max(peak, active);
      await release.promise;
      active--;
      return { type: 'sent' };
    },
  });
  try {
    h.guard.handle({ type: 'message', message: message(1) });
    await new Promise(resolve => setImmediate(resolve));
    for (let id = 2; id <= 501; id++) {
      h.guard.handle({ type: 'message', message: message(id) });
      if (id % 100 === 0) await new Promise(resolve => setImmediate(resolve));
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.calls.filter(call => call.type === 'scam:check').length, 501);
    assert.deepEqual(h.notices.filter(code => code.endsWith('_QUEUE_FULL')), []);
    for (let i = 0; i < others.length; i++) {
      h.guard.handle({ type: 'message', message: message(1000 + i, { channelId: others[i] }) });
      await new Promise(resolve => setImmediate(resolve));
    }
    assert.deepEqual(h.sends.map(send => send.replyTo), ['1', '1000', '1001', '1002']);
    assert.equal(active, 4);
    assert.deepEqual(h.notices.filter(code => code.endsWith('_QUEUE_FULL')), ['NOTIFICATION_QUEUE_FULL']);
    // The busy chat must not consume a 501st waiting slot either.
    h.guard.handle({ type: 'message', message: message(502) });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(h.notices.filter(code => code === 'NOTIFICATION_QUEUE_FULL').length, 2);
  } finally {
    release.resolve();
    await h.guard.whenIdle();
  }
  assert.equal(peak, 4);
  assert.deepEqual(h.sends.map(send => send.replyTo).sort((a, b) => Number(a) - Number(b)), [
    ...Array.from({ length: 501 }, (_, i) => String(i + 1)), '1000', '1001', '1002',
  ]);
});
