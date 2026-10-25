import test from 'node:test';
import assert from 'node:assert/strict';
import { IntentReviewer } from '../dist/review.js';

const reply = (body, status = 200) => async (url, init) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

test('the reviewer asks Claude for a forced tool verdict and treats the message as data', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init, body: JSON.parse(init.body) }); return reply({ content: [{ type: 'tool_use', name: 'report_intent', input: { scam: true } }] })(); };
  const reviewer = new IntentReviewer({ apiKey: 'sk-secret', model: 'claude-haiku-5-5', fetchImpl });
  assert.equal(await reviewer.isScam('加我投資群', 0.65), true);
  const [call] = calls;
  assert.equal(call.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(call.init.headers['x-api-key'], 'sk-secret');
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.body.model, 'claude-haiku-5-5');
  assert.deepEqual(call.body.tool_choice, { type: 'tool', name: 'report_intent' });
  assert.ok(call.body.messages[0].content.includes('<message>\n加我投資群\n</message>'));
  assert.ok(!JSON.stringify(call.body).includes('sk-secret'));
});

test('a false verdict is returned, and bad or failed responses throw codes without the key or body', async () => {
  const no = new IntentReviewer({ apiKey: 'sk-secret', model: 'm', fetchImpl: reply({ content: [{ type: 'tool_use', name: 'report_intent', input: { scam: false } }] }) });
  assert.equal(await no.isScam('x', 0.7), false);
  for (const [fetchImpl, code] of [
    [reply({ content: [{ type: 'text', text: 'scam' }] }), 'REVIEW_INVALID_RESPONSE'],
    [reply({ content: [{ type: 'tool_use', name: 'report_intent', input: { scam: 'yes' } }] }), 'REVIEW_INVALID_RESPONSE'],
    [reply({ error: 'sk-secret' }, 401), 'REVIEW_FAILED'],
    [async () => { throw new Error('sk-secret boom'); }, 'REVIEW_FAILED'],
  ]) {
    await assert.rejects(new IntentReviewer({ apiKey: 'sk-secret', model: 'm', fetchImpl }).isScam('x', 0.7), (error) => error.message === code);
  }
});
