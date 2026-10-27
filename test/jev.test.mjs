import test from 'node:test';
import assert from 'node:assert/strict';
import { CrownChecker, ScamChecker } from '../dist/jev.js';

const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);

function fakeFetch(routes) {
  const calls = [];
  return { calls, fetchImpl: async (url, init) => { calls.push({ url: String(url), init }); return routes(String(url), init); } };
}

test('fetches the OpenChat preview and asks TypeSafe with one referenced image behind the opt-in header', async () => {
  const { calls, fetchImpl } = fakeFetch((url) => url.startsWith('https://obs.line-scdn.net/')
    ? new Response(jpeg)
    : new Response(JSON.stringify({ answers: { crown: { type: 'noul', noul: 0.82 } } })));
  const checker = new CrownChecker({ token: 'ts_secret', model: 'jev-1.13.0', fetchImpl });
  assert.equal(await checker.check('0hABC_def-1'), 0.82);
  assert.equal(calls[0].url, 'https://obs.line-scdn.net/0hABC_def-1/preview');
  assert.equal(calls[0].init.redirect, 'error');
  const { init } = calls[1];
  assert.equal(calls[1].url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(init.headers.Authorization, 'Bearer ts_secret');
  assert.equal(init.headers['TypeSafe-Danger-Zone-Images'], 'true');
  assert.equal(init.redirect, 'error');
  const body = JSON.parse(init.body);
  const [reference] = Object.keys(body.assets);
  assert.equal(body.state.avatar, reference);
  assert.deepEqual(body.assets[reference], { type: 'image', format: 'jpg', data_base64: jpeg.toString('base64') });
});

test('a missing picture is null without a paid call; unreadable formats and answers fail with codes only', async () => {
  const gone = fakeFetch(() => new Response('', { status: 404 }));
  assert.equal(await new CrownChecker({ token: 't', model: 'm', fetchImpl: gone.fetchImpl }).check('h'), null);
  assert.equal(gone.calls.length, 1);
  const gif = fakeFetch(() => new Response(Buffer.from('GIF89a')));
  await assert.rejects(new CrownChecker({ token: 't', model: 'm', fetchImpl: gif.fetchImpl }).check('h'), /^Error: CROWN_PICTURE_UNSUPPORTED$/);
  assert.equal(gif.calls.length, 1, 'nothing is sent to TypeSafe');
  for (const answer of [{ status: 401, body: 'invalid key ts_secret' }, { status: 200, body: '{"answers":{"crown":{"noul":1.5}}}' }, { status: 200, body: 'not json' }]) {
    const bad = fakeFetch((url) => url.includes('obs.') ? new Response(jpeg) : new Response(answer.body, { status: answer.status }));
    await assert.rejects(new CrownChecker({ token: 'ts_secret', model: 'm', fetchImpl: bad.fetchImpl }).check('h'), (error) => error.message === 'CROWN_CHECK_FAILED');
  }
});

test('scam check sends only the text to TypeSafe and reads probability and a known tactic', async () => {
  const { calls, fetchImpl } = fakeFetch(() => new Response(JSON.stringify({ answers: {
    scam: { type: 'noul', noul: 0.91 }, tactic: { type: 'choice', choice: 'investment', confidence: 0.7 },
  } })));
  const checker = new ScamChecker({ token: 'ts_secret', model: 'jev-1.13.0', fetchImpl });
  assert.deepEqual(await checker.check('加我投資群'), { probability: 0.91, tactic: { kind: 'investment', confidence: 0.7 } });
  assert.equal(calls[0].url, 'https://api.typesafe.ai/v1/systemone');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer ts_secret');
  assert.equal(calls[0].init.redirect, 'error');
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.state, '加我投資群');
  assert.equal(body.model, 'jev-1.13.0');
  assert.deepEqual(Object.keys(body.questions), ['scam', 'tactic']);

  const unknownTactic = fakeFetch(() => new Response('{"answers":{"scam":{"noul":0.2},"tactic":{"choice":"weird","confidence":0.9}}}'));
  assert.deepEqual(await new ScamChecker({ token: 't', model: 'm', fetchImpl: unknownTactic.fetchImpl }).check('x'), { probability: 0.2 });
  for (const answer of [{ status: 401, body: 'invalid key ts_secret' }, { status: 200, body: '{"answers":{"scam":{"noul":1.5}}}' }, { status: 200, body: 'not json' }]) {
    const bad = fakeFetch(() => new Response(answer.body, { status: answer.status }));
    await assert.rejects(new ScamChecker({ token: 'ts_secret', model: 'm', fetchImpl: bad.fetchImpl }).check('x'), (error) => error.message === 'SCAM_CHECK_FAILED');
  }
  const offline = { fetchImpl: async () => { throw new TypeError('fetch failed ts_secret'); } };
  await assert.rejects(new ScamChecker({ token: 'ts_secret', model: 'm', ...offline }).check('x'), (error) => error.message === 'SCAM_CHECK_FAILED');
});
