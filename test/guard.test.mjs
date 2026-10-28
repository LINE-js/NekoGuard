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
const note = (extra = {}) => ({
  type: 'chat:note-posted', chatId, messageId: '10', postId: 'post_1', senderId,
  senderName: '  小語 Alice  ', createdAt: 1, preview: '投資',
  text: '加入投資群組，先匯款解鎖保證獲利。', ...extra,
});

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
    if (type === 'avatar:check') {
      if (options.avatar) return options.avatar(fields);
      return { type: 'avatar:result', ...fields, analysis: { probability: options.crown ?? 0 } };
    }
    if (type === 'message:send') {
      sends.push(fields);
      if (options.send) return options.send(fields);
      return { type: 'sent', messageId: String(100 + sends.length) };
    }
    throw new Error('unexpected request');
  } };
  const guard = new ScamGuard(api, { thresholdPercent: options.threshold ?? 70, crownThresholdPercent: options.crownThreshold ?? 70, ...(options.review ? { review: options.review } : {}), ...(options.scam ? { scam: options.scam } : {}), ...(options.direct === undefined ? {} : { directAlertPercent: options.direct }), checkIntervalMs: 0, sendIntervalMs: 0, adminIntervalMs: 0, ...options.intervals });
  guard.on('notice', code => notices.push(code));
  guard.on('fatal', code => notices.push(code));
  const ready = () => {
    guard.handle({ type: 'hello', protocol: 2, capabilities: options.capabilities ?? ['chat:admins', 'member:join'] });
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

for (const shift of [-60_000, 60_000]) {
  test(`wall-clock adjustments (${shift}ms) neither bypass nor stall API pacing`, async t => {
    const now = Date.now;
    let offset = 0;
    t.mock.method(Date, 'now', () => now() + offset);
    const dispatches = [];
    const h = harness({
      intervals: { checkIntervalMs: 20, adminIntervalMs: 20, sendIntervalMs: 20 },
      onRequest: type => {
        dispatches.push({ type, at: performance.now() });
        offset += shift;
      },
    });
    // Bound a regressed backwards-clock stall without leaving its timers alive.
    const deadline = setTimeout(() => h.guard.stop(), 2500);
    try {
      h.guard.handle({ type: 'message', message: message(1) });
      h.guard.handle({ type: 'message', message: message(2) });
      await h.guard.whenIdle();
      assert.equal(h.sends.length, 2);
      for (const [type, count] of [['scam:check', 2], ['chat:admins:get', 3], ['message:send', 2]]) {
        const times = dispatches.filter(call => call.type === type).map(call => call.at);
        assert.equal(times.length, count);
        for (let i = 1; i < times.length; i++) assert(times[i] - times[i - 1] >= 19.5, type);
      }
    } finally {
      clearTimeout(deadline);
      h.guard.stop();
      await h.guard.whenIdle();
    }
  });
}

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

const joinerId = 'p' + 'e'.repeat(32);
const join = (displayName, extra = {}) => ({ type: 'member:join', chatId, member: { userId: joinerId, displayName }, ...extra });

test('a join alerts on a crown at the inclusive threshold or an admin-like name, checking the picture before the name', async () => {
  for (const [crown, name, expected] of [[0.699999, '小明', false], [0.7, '小明', true], [0, '群管小幫手', true], [null, '管 理 員', true], [null, '小明', false]]) {
    const h = harness({ avatar: fields => ({ type: 'avatar:result', ...fields, ...(crown === null ? {} : { analysis: { probability: crown } }) }) });
    h.guard.handle(join(name));
    await h.guard.whenIdle();
    assert.equal(h.calls.filter(call => call.type === 'avatar:check').length, 1, 'the picture is judged even when the name already matches');
    assert.equal(h.sends.length > 0, expected, `${crown} ${name}`);
    if (!expected) continue;
    const [send] = h.sends;
    assert.equal(send.replyTo, undefined);
    assert.deepEqual(send.mentions.map(mention => mention.userId), [admin.userId], 'the newcomer is named in text, never mentioned');
    assert.ok(send.text.includes(joinerId));
  }
});

test('an unjudged picture never hides a name finding, and joins honor scope, own identity and capability', async () => {
  const h = harness({ avatar: () => { throw new ApiError('AVATAR_CHECK_UNAVAILABLE'); } });
  h.guard.handle(join('Admin_Amy'));
  await h.guard.whenIdle();
  assert.equal(h.sends.length, 1);
  assert.ok(h.sends[0].text.includes('未能判定'));
  assert.ok(h.notices.includes('AVATAR_CHECK_UNAVAILABLE'));

  const scoped = harness({ crown: 1 });
  scoped.guard.handle(join('管理', { chatId: 'm' + 'z'.repeat(32) }));
  scoped.guard.handle(join('管理', { member: { userId: ownId, displayName: '管理' } }));
  await scoped.guard.whenIdle();
  assert.deepEqual(scoped.calls.filter(call => call.type === 'avatar:check'), [], 'unscoped chat and own identity are never checked');

  const old = harness({ crown: 1, capabilities: ['chat:admins'] });
  assert.ok(old.notices.includes('LINEJS_MEMBER_JOIN_EXTENSION_REQUIRED'));
  old.guard.handle(join('群管'));
  old.guard.handle({ type: 'message', message: message(1) });
  await old.guard.whenIdle();
  assert.deepEqual(old.calls.filter(call => call.type === 'avatar:check'), []);
  assert.equal(old.sends.length, 1, 'scam monitoring keeps working on an older extension');
});

test('joins share the paid-check pacing with scam checks, and a rejoin or account change drops a pending check', async () => {
  const gate = Promise.withResolvers();
  let checks = 0;
  const h = harness({ avatar: async fields => { checks += 1; if (checks === 1) await gate.promise; return { type: 'avatar:result', ...fields, analysis: { probability: 1 } }; } });
  h.guard.handle(join('小明'));
  await new Promise(resolve => setImmediate(resolve));
  h.guard.handle(join('小明'));
  gate.resolve();
  await h.guard.whenIdle();
  assert.equal(checks, 2);
  assert.equal(h.sends.length, 1, 'only the latest join may alert');

  const paced = harness({ intervals: { checkIntervalMs: 60_000 } });
  paced.guard.handle({ type: 'message', message: message(1) });
  paced.guard.handle(join('群管'));
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.deepEqual(paced.calls.filter(call => call.type === 'scam:check' || call.type === 'avatar:check').map(call => call.type), ['scam:check']);
  paced.guard.handle({ type: 'auth:state', state: 'logged_out' });
  await paced.guard.whenIdle();
  assert.equal(paced.calls.some(call => call.type === 'avatar:check'), false);
});

test('newer LINE.js chat:member-joined frames are checked: the reported name alerts and the picture is judged locally', async () => {
  const hash = '0hlU0hKiRrM3oNES_EmNxMLTJHblR8dSh_ZTRiXSkZa0gidHMsYyJ7SyAZbxggJyF5N3F_GS0Za010JSYq';
  const upstream = (member) => ({ type: 'chat:member-joined', chatId, member: { userId: joinerId, ...member } });
  const judged = [];
  const h = harness({ capabilities: ['chat:admins', 'chat:admin-token', 'chat:member-joined'] });
  // Rebuild with a local crown checker, as main.ts does when jev.token is configured.
  const { ScamGuard: Guard } = await import('../dist/guard.js');
  const sends = [];
  const api = { async request(type, fields) {
    if (type === 'chat:admins:get') return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: ownId, admins: [admin] };
    if (type === 'message:send') { sends.push(fields); return { type: 'sent', messageId: '1' }; }
    throw new Error(`unexpected ${type}`);
  } };
  const guard = new Guard(api, { thresholdPercent: 70, crownThresholdPercent: 70, checkIntervalMs: 0, sendIntervalMs: 0, adminIntervalMs: 0, crown: async (pictureHash) => { judged.push(pictureHash); return 0.9; } });
  guard.handle({ type: 'hello', protocol: 2, capabilities: ['chat:admins', 'chat:admin-token', 'chat:member-joined'] });
  guard.handle({ type: 'auth:ready', profile: { userId } });
  guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind: 'square' }] });
  guard.handle(upstream({ displayName: '\uFFFC管管-星語', pictureId: `avatar-o-${hash}` }));
  await guard.whenIdle();
  assert.deepEqual(judged, [hash]);
  assert.equal(sends.length, 1);
  assert.ok(sends[0].text.includes('假皇冠機率：90%\n') && sends[0].text.includes('名稱含管理員相關字詞：是'));

  // Without a local key: no avatar:check request to a backend that lacks it, the name still alerts.
  assert.ok(h.notices.includes('CROWN_CHECK_DISABLED'));
  h.guard.handle(upstream({ displayName: '\uFFFC管管-星語', pictureId: `avatar-o-${hash}` }));
  await h.guard.whenIdle();
  assert.equal(h.calls.some(call => call.type === 'avatar:check'), false);
  assert.equal(h.sends.length, 1);
  assert.ok(h.sends[0].text.includes('未能判定'));
});

test('a joiner without a picture is not sent for judging and is reported as having none', async () => {
  const judged = [];
  const { ScamGuard: Guard } = await import('../dist/guard.js');
  const sends = [];
  const api = { async request(type, fields) {
    if (type === 'chat:admins:get') return { type: 'chat:admins', chatId: fields.chatId, ownMemberId: ownId, admins: [admin] };
    if (type === 'message:send') { sends.push(fields); return { type: 'sent', messageId: '1' }; }
    throw new Error(`unexpected ${type}`);
  } };
  const guard = new Guard(api, { thresholdPercent: 70, crownThresholdPercent: 70, checkIntervalMs: 0, sendIntervalMs: 0, adminIntervalMs: 0, crown: async (hash) => { judged.push(hash); return 1; } });
  guard.handle({ type: 'hello', protocol: 2, capabilities: ['chat:admins', 'chat:member-joined'] });
  guard.handle({ type: 'auth:ready', profile: { userId } });
  guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind: 'square' }] });
  guard.handle({ type: 'chat:member-joined', chatId, member: { userId: joinerId, displayName: '群管' } });
  guard.handle({ type: 'chat:member-joined', chatId, member: { userId: 'p' + 'f'.repeat(32), displayName: '小明', pictureId: 'avatar-o-../../etc' } });
  await guard.whenIdle();
  assert.deepEqual(judged, [], 'a malformed picture id is never fetched');
  assert.equal(sends.length, 1);
  assert.ok(sends[0].text.includes('假皇冠機率：0%\n'));
});

test('every judged join reports its verdict, including ones that raise no alert', async () => {
  const h = harness({ crown: 0.1 });
  const verdicts = [];
  h.guard.on('join', verdict => verdicts.push(verdict));
  h.guard.handle(join('小明'));
  await h.guard.whenIdle();
  assert.deepEqual(verdicts, [{ chatId, memberId: joinerId, crown: 0.1, crownHit: false, nameHit: false, alert: false }]);
  assert.equal(h.sends.length, 0);
});

test('a detector hit is marked at once without mentions; only a scam intent then mentions every admin', async () => {
  const seen = [];
  for (const verdict of [false, true]) {
    const h = harness({ probability: 0.9, review: async (text, probability) => { seen.push([text, probability]); return verdict; } });
    h.guard.handle({ type: 'message', message: message(1) });
    await h.guard.whenIdle();
    const [mark, ...alerts] = h.sends;
    assert.equal(mark.replyTo, '1');
    assert.deepEqual(mark.mentions, []);
    assert.ok(mark.text.startsWith('疑似詐騙預警\n詐騙機率：90%'));
    assert.equal(alerts.length, verdict ? 1 : 0);
    if (verdict) {
      assert.equal(alerts[0].replyTo, '1');
      assert.deepEqual(alerts[0].mentions.map(m => m.userId), [admin.userId]);
      assert.ok(alerts[0].text.includes('發言意圖經分析判定為詐騙'));
    }
    // Identity discovery looks up once; the stage-one mark adds none, the mention adds one.
    assert.equal(h.calls.filter(call => call.type === 'chat:admins:get').length, verdict ? 2 : 1);
  }
  assert.deepEqual(seen, [['投資邀請', 0.9], ['投資邀請', 0.9]]);
});

test('a failed review still mentions the admins and says the intent was not analysed; below-threshold messages are never reviewed', async () => {
  const failing = harness({ probability: 0.9, review: async () => { throw new Error('REVIEW_FAILED'); } });
  failing.guard.handle({ type: 'message', message: message(1) });
  await failing.guard.whenIdle();
  assert.equal(failing.sends.length, 2);
  assert.deepEqual(failing.sends[0].mentions, []);
  assert.equal(failing.sends[1].mentions.length, 1);
  assert.ok(failing.sends[1].text.includes('發言意圖分析失敗'));
  assert.ok(failing.notices.includes('REVIEW_FAILED'));

  let reviewed = 0;
  const low = harness({ probability: 0.5, review: async () => { reviewed += 1; return true; } });
  low.guard.handle({ type: 'message', message: message(2) });
  await low.guard.whenIdle();
  assert.equal(reviewed, 0);
  assert.equal(low.sends.length, 0);
});

test('without a reviewer a detector hit mentions the admins directly, with no separate mark', async () => {
  const h = harness({ probability: 0.9 });
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  assert.equal(h.sends.length, 1);
  assert.equal(h.sends[0].mentions.length, 1);
  assert.ok(!h.sends[0].text.includes('發言意圖'));
});

test('at or above the direct alert threshold the admins are mentioned at once without a mark or review; below it the two stages apply', async () => {
  for (const [probability, expectReview] of [[0.9, false], [0.89, true]]) {
    let reviewed = 0;
    const h = harness({ probability, direct: 90, review: async () => { reviewed += 1; return true; } });
    h.guard.handle({ type: 'message', message: message(1) });
    await h.guard.whenIdle();
    assert.equal(reviewed, expectReview ? 1 : 0);
    assert.deepEqual(h.sends.map(send => send.mentions.length), expectReview ? [0, 1] : [1]);
  }
});

test('LINE.js without scam:check: messages are judged locally from their text, never sent as scam:check', async () => {
  const builtIn = ['chat:admins', 'chat:admin-token', 'chat:member-joined'];
  const texts = [];
  const h = harness({ capabilities: builtIn, scam: async text => { texts.push(text); return { probability: 0.9, tactic: { kind: 'investment', confidence: 0.8 } }; } });
  h.guard.handle({ type: 'message', message: message(1) });
  await h.guard.whenIdle();
  assert.deepEqual(texts, ['投資邀請']);
  assert.equal(h.calls.some(call => call.type === 'scam:check'), false);
  assert.equal(h.sends.length, 1);
  assert.ok(h.sends[0].text.includes('詐騙機率：90%'));

  // A failed local check is reported by code and alerts no one.
  const failing = harness({ capabilities: builtIn, scam: async () => { throw new Error('SCAM_CHECK_FAILED'); } });
  failing.guard.handle({ type: 'message', message: message(1) });
  await failing.guard.whenIdle();
  assert.equal(failing.sends.length, 0);
  assert.ok(failing.notices.includes('SCAM_CHECK_FAILED'));

  // No key: say so once instead of timing out on every message.
  const disabled = harness({ capabilities: builtIn });
  disabled.guard.handle({ type: 'message', message: message(1) });
  await disabled.guard.whenIdle();
  assert.ok(disabled.notices.includes('SCAM_CHECK_DISABLED'));
  assert.deepEqual(disabled.calls, []);
});

test('notes require a Jev hit and confirmed intent, including above the message direct threshold; warn without content or mentions', async () => {
  for (const [probability, verdict, expectedReviews, expectedSends] of [
    [0.699999, true, 0, 0], [0.7, false, 1, 0], [0.7, true, 1, 1],
    [0.99, false, 1, 0], [0.99, true, 1, 1],
  ]) {
    const seen = [];
    let reviews = 0;
    const h = harness({
      direct: 90,
      scam: async text => { seen.push(text); return { probability }; },
      review: async (text, score) => {
        reviews++;
        assert.equal(text, note().text);
        assert.equal(score, probability);
        assert.deepEqual(h.sends, []); // No preliminary warning while intent is unconfirmed.
        return verdict;
      },
    });
    h.guard.handle(note());
    await h.guard.whenIdle();
    assert.deepEqual(seen, [note().text]); // Full text, never LINE's abbreviated preview.
    assert.equal(reviews, expectedReviews);
    assert.equal(h.sends.length, expectedSends);
    if (expectedSends) assert.deepEqual(h.sends[0], {
      chatId, text: '「小語 Alice」在記事本的文章屬於詐騙。', mentions: [],
    });
    assert.equal(h.calls.some(call => call.type === 'scam:check'), false);
  }
});

test('notes never analyse previews, empty or malformed posts, unscoped chats, or either own identity', async () => {
  const seen = [];
  const h = harness({
    scam: async text => { seen.push(text); return { probability: 1 }; },
    review: async () => true,
  });
  for (const extra of [
    { text: undefined, error: 'NOTE_FETCH_FAILED' },
    { text: undefined }, { text: '' }, { text: ' \n ' }, { text: ['article'] },
    { postId: '../post' }, { senderName: null }, { messageId: 'bad' },
    { senderId: userId }, { senderId: ownId },
    { chatId: 'm' + 'e'.repeat(32) }, { chatId: 'c' + 'e'.repeat(32) },
  ]) {
    h.guard.handle(note(extra));
    await h.guard.whenIdle();
  }
  assert.deepEqual(seen, []);
  assert.deepEqual(h.sends, []);
  assert.ok(h.notices.includes('NOTE_FETCH_FAILED'));
});

test('notes need both local Jev and intent review configured, never falling back to the message-only backend check', async () => {
  for (const options of [{}, { scam: async () => { throw new Error('unexpected paid check'); } }, { review: async () => true }]) {
    const h = harness({ ...options, capabilities: ['chat:admins', 'chat:member-joined', 'chat:note-posted'] });
    h.guard.handle(note());
    await h.guard.whenIdle();
    assert.ok(h.notices.includes('NOTE_CHECK_DISABLED'));
    assert.deepEqual(h.calls, []);
  }
});

test('notes deduplicate by postId within a chat, including shared notifications with a different messageId', async () => {
  const other = 'm' + 'e'.repeat(32);
  let checks = 0;
  const h = harness({
    chats: [chatId, other],
    scam: async () => { checks++; return { probability: 1 }; },
    review: async () => true,
  });
  h.guard.handle(note());
  h.guard.handle(note({ messageId: '11' }));
  h.guard.handle(note({ chatId: other }));
  await h.guard.whenIdle();
  h.guard.handle(note({ messageId: '12' }));
  await h.guard.whenIdle();
  assert.equal(checks, 2);
  assert.deepEqual(h.sends.map(send => send.chatId).sort(), [chatId, other].sort());
});

test('failed note intent review logs only a code and never declares the article a scam', async () => {
  const h = harness({
    scam: async () => ({ probability: 1 }),
    review: async () => { throw new Error('private article and provider response'); },
  });
  h.guard.handle(note());
  await h.guard.whenIdle();
  assert.deepEqual(h.sends, []);
  assert.deepEqual(h.notices.filter(code => code !== 'MONITORING_READY'), ['REVIEW_FAILED']);
});

test('note warnings are cancelled by take-back, logout, or chat removal while intent review is pending', async () => {
  for (const event of [
    { type: 'message:unsend', chatId, messageId: '10' },
    { type: 'auth:state', state: 'idle' },
    { type: 'channels', channels: [] },
  ]) {
    const gate = Promise.withResolvers();
    const h = harness({ scam: async () => ({ probability: 1 }), review: () => gate.promise });
    h.guard.handle(note());
    await new Promise(resolve => setImmediate(resolve));
    h.guard.handle(event);
    gate.resolve(true);
    await h.guard.whenIdle();
    assert.deepEqual(h.sends, []);
  }
});

test('group notes use account identity without OpenChat admin lookup, while ordinary messages and join checks stay OpenChat-only', async () => {
  const groupId = 'c' + 'e'.repeat(32);
  const texts = [];
  const h = harness({
    scam: async text => { texts.push(text); return { probability: 0.99 }; },
    review: async () => true,
  });
  h.guard.handle({ type: 'channels', channels: [{ channelId: groupId, kind: 'group' }] });
  h.guard.handle(note({ chatId: groupId, senderId: userId }));
  h.guard.handle({ type: 'message', message: message(11, { channelId: groupId, channelKind: 'group' }) });
  h.guard.handle({ type: 'member:join', chatId: groupId, member: { userId: senderId, displayName: 'admin' } });
  h.guard.handle(note({ chatId: groupId, senderId: 'u' + 'f'.repeat(32) }));
  await h.guard.whenIdle();
  assert.deepEqual(texts, [note().text]);
  assert.deepEqual(h.calls.map(call => call.type), ['message:send']);
  assert.deepEqual(h.sends[0], { chatId: groupId, text: '「小語 Alice」在記事本的文章屬於詐騙。', mentions: [] });
});

test('OpenChat note status events accept no messageId and optional or opaque writer identity; deduplicate across both event sources', async () => {
  for (const author of [
    { senderId, senderName: '作者' },
    { senderId: 'writer_opaque-id', senderName: '作者' },
    { senderId: undefined, senderName: undefined },
  ]) {
    const texts = [];
    const h = harness({
      scam: async text => { texts.push(text); return { probability: 1 }; },
      review: async () => true,
    });
    h.guard.handle(note({ messageId: undefined, ...author }));
    h.guard.handle(note());
    await h.guard.whenIdle();
    assert.deepEqual(texts, [note().text]);
    assert.equal(h.sends.length, 1);
    assert.deepEqual(h.sends[0].mentions, []);
    assert.equal(h.sends[0].replyTo, undefined);
    assert.ok(h.sends[0].text.includes(author.senderName ? '「作者」' : '「（未提供名稱）」'));
    assert.equal(h.sends[0].text.includes(note().text), false);
  }
});

test('note list failures without post or writer ids are reported but never analyse a preview', async () => {
  let checks = 0;
  const h = harness({
    scam: async () => { checks++; return { probability: 1 }; },
    review: async () => true,
  });
  h.guard.handle(note({
    postId: undefined, messageId: undefined, senderId: undefined, senderName: undefined,
    text: undefined, error: 'NOTE_FETCH_FAILED',
  }));
  h.guard.handle(note({ postId: undefined }));
  await h.guard.whenIdle();
  assert.equal(checks, 0);
  assert.ok(h.notices.includes('NOTE_FETCH_FAILED'));
  assert.deepEqual(h.sends, []);
});

test('group and message-less OpenChat note reviews are invalidated when their chat is removed', async () => {
  for (const kind of ['group', 'square']) {
    const gate = Promise.withResolvers();
    const started = Promise.withResolvers();
    const h = harness({
      scam: async () => ({ probability: 1 }),
      review: () => { started.resolve(); return gate.promise; },
    });
    h.guard.handle({ type: 'channels', channels: [{ channelId: chatId, kind }] });
    h.guard.handle(note({ messageId: undefined }));
    await started.promise;
    h.guard.handle({ type: 'channels', channels: [] });
    gate.resolve(true);
    await h.guard.whenIdle();
    assert.deepEqual(h.sends, []);
  }
});
