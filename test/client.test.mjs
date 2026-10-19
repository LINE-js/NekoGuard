import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import { ApiClient } from '../dist/client.js';

async function connect(t, timeoutMs = 5000) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  t.after(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise(resolve => server.close(resolve));
  });
  await once(server, 'listening');
  const client = new ApiClient(`ws://127.0.0.1:${server.address().port}/api/ws`, 'test-token', timeoutMs);
  t.after(() => client.close());
  const connected = once(server, 'connection');
  await client.connect();
  const [socket] = await connected;
  return { client, socket };
}

// More than 36 simultaneous requests crosses a base-36 ID width boundary.
test('out-of-order responses remain isolated across concurrent requests and API errors', async t => {
  const { client, socket } = await connect(t);
  const received = [];
  socket.on('message', bytes => {
    const request = JSON.parse(bytes.toString());
    assert.match(request.requestId, /^[A-Za-z0-9_-]{1,64}$/);
    received.push(request);
    if (received.length !== 40) return;
    assert.equal(new Set(received.map(frame => frame.requestId)).size, 40);
    for (const frame of received.toReversed()) {
      socket.send(JSON.stringify(frame.messageId === '17'
        ? { type: 'error', requestId: frame.requestId, code: 'RATE_LIMITED' }
        : { type: 'scam:result', requestId: frame.requestId, analysis: { probability: Number(frame.messageId) / 40 } }));
    }
  });
  const results = await Promise.allSettled(Array.from({ length: 40 }, (_, i) =>
    client.request('scam:check', { chatId: 'm' + 'a'.repeat(32), messageId: String(i) }, 'scam:result')));
  for (let i = 0; i < results.length; i++) {
    if (i === 17) {
      assert.equal(results[i].status, 'rejected');
      assert.equal(results[i].reason.code, 'RATE_LIMITED');
    } else {
      assert.equal(results[i].status, 'fulfilled');
      assert.equal(results[i].value.analysis.probability, i / 40);
    }
  }
});

test('a late response to a timed-out request cannot settle a newer request', async t => {
  const { client, socket } = await connect(t, 200);
  const firstReceived = once(socket, 'message');
  const first = client.request('scam:check', { chatId: 'm' + 'a'.repeat(32), messageId: '1' }, 'scam:result');
  const timedOut = assert.rejects(first, { code: 'REQUEST_TIMEOUT' });
  const [firstBytes] = await firstReceived;
  const oldRequest = JSON.parse(firstBytes.toString());
  await timedOut;

  const nextReceived = once(socket, 'message');
  const next = client.request('scam:check', { chatId: 'm' + 'a'.repeat(32), messageId: '2' }, 'scam:result');
  const [nextBytes] = await nextReceived;
  const newRequest = JSON.parse(nextBytes.toString());
  assert.notEqual(newRequest.requestId, oldRequest.requestId);
  const lateReceived = once(client, 'frame');
  socket.send(JSON.stringify({ type: 'scam:result', requestId: oldRequest.requestId, analysis: { probability: 1 } }));
  await lateReceived;
  socket.send(JSON.stringify({ type: 'scam:result', requestId: newRequest.requestId, analysis: { probability: 0 } }));
  assert.equal((await next).analysis.probability, 0);
});

test('unserializable fields reject without transmitting or leaving orphaned requests', async t => {
  const { client, socket } = await connect(t);
  const received = [];
  socket.on('message', bytes => {
    const frame = JSON.parse(bytes.toString());
    received.push(frame.messageId);
    socket.send(JSON.stringify({
      type: 'scam:result', requestId: frame.requestId, analysis: { probability: 0.25 },
    }));
  });
  const circular = {};
  circular.self = circular;
  for (const fields of [
    { circular },
    { messageId: 1n },
    { get text() { throw new Error('sensitive input must not escape'); } },
  ]) {
    await assert.rejects(client.request('scam:check', fields, 'scam:result'), {
      code: 'INVALID_REQUEST', message: 'INVALID_REQUEST',
    });
  }
  const result = await client.request('scam:check', { messageId: 'valid' }, 'scam:result');
  assert.equal(result.analysis.probability, 0.25);
  assert.deepEqual(received, ['valid']);
  // Closing rejects any leaked pending promise; node:test also fails on unhandled rejections.
  client.close();
  await new Promise(resolve => setImmediate(resolve));
});
