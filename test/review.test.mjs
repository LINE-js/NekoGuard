import test from 'node:test';
import assert from 'node:assert/strict';
import { AnthropicReviewer, OpenAIReviewer, ReviewChain } from '../dist/review.js';

const reply = (body, status = 200) => async () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const openaiVerdict = (scam, extra = {}) => ({
  status: 'completed',
  output: [
    { type: 'reasoning', summary: [] },
    { type: 'message', content: [{ type: 'output_text', text: JSON.stringify({ analysis: 'x', scam }) }] },
  ],
  ...extra,
});

test('the Claude reviewer asks for a forced tool verdict and treats the message as data', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init, body: JSON.parse(init.body) }); return reply({ content: [{ type: 'tool_use', name: 'report_intent', input: { scam: true } }] })(); };
  const reviewer = new AnthropicReviewer({ apiKey: 'sk-secret', model: 'claude-haiku-5-5', fetchImpl });
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

test('the OpenAI reviewer uses an unstored strict-schema Responses request and reads the message after reasoning items', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init, body: JSON.parse(init.body) }); return reply(openaiVerdict(true))(); };
  const reviewer = new OpenAIReviewer({ apiKey: 'sk-openai', model: 'gpt-6-luna', fetchImpl });
  assert.equal(await reviewer.isScam('加我投資群', 0.65), true);
  const [call] = calls;
  assert.equal(call.url, 'https://api.openai.com/v1/responses');
  assert.equal(call.init.headers.Authorization, 'Bearer sk-openai');
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.body.model, 'gpt-6-luna');
  assert.equal(call.body.store, false);
  assert.deepEqual(call.body.text.format.type, 'json_schema');
  assert.equal(call.body.text.format.strict, true);
  assert.deepEqual(call.body.text.format.schema.required, ['analysis', 'scam']);
  assert.equal(call.body.text.format.schema.additionalProperties, false);
  assert.ok(call.body.input.includes('<message>\n加我投資群\n</message>'));
  assert.ok(call.body.instructions.includes('untrusted data'));
  assert.ok(!JSON.stringify(call.body).includes('sk-openai'));
  assert.equal(await new OpenAIReviewer({ apiKey: 'k', model: 'm', fetchImpl: reply(openaiVerdict(false)) }).isScam('x', 0.7), false);
});

test('each provider reports bad, refused, incomplete or failed responses as codes without the key or body', async () => {
  for (const [Reviewer, fetchImpl, code] of [
    [AnthropicReviewer, reply({ content: [{ type: 'text', text: 'scam' }] }), 'REVIEW_INVALID_RESPONSE'],
    [AnthropicReviewer, reply({ content: [{ type: 'tool_use', name: 'report_intent', input: { scam: 'yes' } }] }), 'REVIEW_INVALID_RESPONSE'],
    [AnthropicReviewer, reply({ error: 'sk-secret' }, 401), 'REVIEW_FAILED'],
    [AnthropicReviewer, async () => { throw new Error('sk-secret boom'); }, 'REVIEW_FAILED'],
    [OpenAIReviewer, reply({ status: 'completed', output: [{ type: 'message', content: [{ type: 'refusal', refusal: 'no' }] }] }), 'REVIEW_REFUSED'],
    [OpenAIReviewer, reply(openaiVerdict(true, { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' } })), 'REVIEW_INVALID_RESPONSE'],
    [OpenAIReviewer, reply({ status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: '{"scam":"yes"}' }] }] }), 'REVIEW_INVALID_RESPONSE'],
    [OpenAIReviewer, reply({ status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'not json' }] }] }), 'REVIEW_INVALID_RESPONSE'],
    [OpenAIReviewer, reply({ error: { message: 'sk-secret' } }, 429), 'REVIEW_FAILED'],
  ]) {
    await assert.rejects(new Reviewer({ apiKey: 'sk-secret', model: 'm', fetchImpl }).isScam('x', 0.7), (error) => error.message === code);
  }
});

test('the chain keeps the primary verdict, falls back only on failure, and reports the backup failure last', async () => {
  const stub = (provider, outcome) => ({ provider, calls: 0, async isScam() { this.calls++; if (outcome instanceof Error) throw outcome; return outcome; } });
  for (const verdict of [true, false]) {
    const primary = stub('openai', verdict), backup = stub('anthropic', !verdict), fallbacks = [];
    assert.equal(await new ReviewChain([primary, backup], (...args) => fallbacks.push(args)).isScam('x', 0.7), verdict);
    assert.equal(backup.calls, 0, 'a dismissal by the primary is final, not retried elsewhere');
    assert.deepEqual(fallbacks, []);
  }
  const fallbacks = [];
  const backup = stub('anthropic', true);
  assert.equal(await new ReviewChain([stub('openai', new Error('REVIEW_REFUSED')), backup], (...args) => fallbacks.push(args)).isScam('x', 0.7), true);
  assert.deepEqual(fallbacks, [['openai', 'anthropic', 'REVIEW_REFUSED']]);
  const leaky = [];
  await assert.rejects(
    new ReviewChain([stub('anthropic', new Error('private text sk-secret')), stub('openai', new Error('REVIEW_INVALID_RESPONSE'))], (...args) => leaky.push(args)).isScam('x', 0.7),
    (error) => error.message === 'REVIEW_INVALID_RESPONSE',
  );
  assert.deepEqual(leaky, [['anthropic', 'openai', 'REVIEW_FAILED']], 'unexpected errors are reduced to a fixed code');
});
