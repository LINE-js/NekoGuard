import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../dist/config.js';

async function withConfig(contents, action) {
  const directory = await mkdtemp(join(tmpdir(), 'nekoguard-config-'));
  const previous = process.env.NEKOGUARD_API_TOKEN;
  delete process.env.NEKOGUARD_API_TOKEN;
  try {
    const path = join(directory, 'config.yaml');
    await writeFile(path, contents);
    await action(path);
  } finally {
    if (previous === undefined) delete process.env.NEKOGUARD_API_TOKEN;
    else process.env.NEKOGUARD_API_TOKEN = previous;
    await rm(directory, { recursive: true, force: true });
  }
}

function yaml(threshold = '70', url = 'ws://127.0.0.1:3789/api/ws', token = 'file-secret') {
  return `api:\n  url: ${JSON.stringify(url)}\n  token: ${JSON.stringify(token)}\ndetection:\n  thresholdPercent: ${threshold}\n`;
}

test('loads inclusive thresholds and environment token override', async () => {
  for (const threshold of [0, 69.99, 70, 100]) {
    await withConfig(yaml(String(threshold)), async (path) => {
      const config = await loadConfig(path);
      assert.equal(config.detection.thresholdPercent, threshold);
      assert.equal(config.api.token, 'file-secret');
      process.env.NEKOGUARD_API_TOKEN = 'environment-secret';
      assert.equal((await loadConfig(path)).api.token, 'environment-secret');
    });
  }
});

test('rejects invalid threshold values instead of coercing', async () => {
  for (const threshold of ['-1', '100.01', '.nan', '.inf', '"70"', 'null']) {
    await withConfig(yaml(threshold), async (path) => {
      await assert.rejects(loadConfig(path), /thresholdPercent/);
    });
  }
});

test('the crown threshold is optional, independent and validated like the scam threshold', async () => {
  await withConfig(yaml('90'), async (path) => assert.equal((await loadConfig(path)).detection.crownThresholdPercent, 70));
  await withConfig(`${yaml('90')}  crownThresholdPercent: 55.5\n`, async (path) => {
    assert.deepEqual((await loadConfig(path)).detection, { thresholdPercent: 90, crownThresholdPercent: 55.5 });
  });
  for (const value of ['-1', '101', '"70"', 'null']) {
    await withConfig(`${yaml()}  crownThresholdPercent: ${value}\n`, async (path) => {
      await assert.rejects(loadConfig(path), /crownThresholdPercent/);
    });
  }
});

test('permits only secure remote endpoints or loopback ws endpoints', async () => {
  for (const url of ['ws://localhost:3789/api/ws', 'ws://[::1]:3789/api/ws', 'wss://example.com/api/ws']) {
    await withConfig(yaml('70', url), async (path) => assert.equal((await loadConfig(path)).api.url, url));
  }
  for (const url of ['ws://example.com/api/ws', 'https://localhost/api/ws', 'ws://localhost/wrong', 'ws://localhost/api/ws?', 'ws://localhost/api/ws#', 'wss://user:secret@example.com/api/ws']) {
    await withConfig(yaml('70', url), async (path) => {
      await assert.rejects(loadConfig(path), (error) => !error.message.includes(url) && !error.message.includes('secret'));
    });
  }
});

test('rejects empty tokens including explicit empty environment overrides', async () => {
  await withConfig(yaml('70', undefined, ''), async (path) => assert.rejects(loadConfig(path), /non-empty API token/));
  await withConfig(yaml(), async (path) => {
    process.env.NEKOGUARD_API_TOKEN = '';
    await assert.rejects(loadConfig(path), /non-empty API token/);
  });
});

test('does not leak YAML source or invalid credentials in errors', async () => {
  await withConfig('api: [TOP-SECRET\n', async (path) => {
    await assert.rejects(loadConfig(path), (error) => !error.message.includes('TOP-SECRET'));
  });
  await withConfig(yaml('70', undefined, 'TOP-SECRET\n'), async (path) => {
    await assert.rejects(loadConfig(path), (error) => !error.message.includes('TOP-SECRET'));
  });
});

test('the TypeSafe key is optional, environment-overridable and validated without echoing it', async () => {
  const previous = process.env.NEKOGUARD_JEV_TOKEN;
  delete process.env.NEKOGUARD_JEV_TOKEN;
  try {
    await withConfig(yaml(), async (path) => assert.equal((await loadConfig(path)).jev, undefined));
    await withConfig(`${yaml()}jev:\n  token: ts_file\n`, async (path) => {
      assert.deepEqual((await loadConfig(path)).jev, { token: 'ts_file', model: 'jev-1.13.0' });
      process.env.NEKOGUARD_JEV_TOKEN = 'ts_env';
      assert.equal((await loadConfig(path)).jev.token, 'ts_env');
      delete process.env.NEKOGUARD_JEV_TOKEN;
    });
    await withConfig(`${yaml()}jev:\n  token: "ts secret"\n`, async (path) => {
      await assert.rejects(loadConfig(path), (error) => /jev\.token/.test(error.message) && !error.message.includes('secret'));
    });
  } finally {
    if (previous === undefined) delete process.env.NEKOGUARD_JEV_TOKEN;
    else process.env.NEKOGUARD_JEV_TOKEN = previous;
  }
});

test('review providers: OpenAI is primary by default, Claude backs it up, and the order is switchable', async () => {
  const names = ['NEKOGUARD_OPENAI_API_KEY', 'NEKOGUARD_ANTHROPIC_API_KEY', 'NEKOGUARD_REVIEW_API_KEY'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  for (const name of names) delete process.env[name];
  const both = 'review:\n  openai:\n    apiKey: sk-openai\n  anthropic:\n    apiKey: sk-claude\n';
  try {
    await withConfig(yaml(), async (path) => assert.equal((await loadConfig(path)).review, undefined));
    await withConfig(`${yaml()}${both}`, async (path) => assert.deepEqual((await loadConfig(path)).review, [
      { provider: 'openai', apiKey: 'sk-openai', model: 'gpt-6-luna' },
      { provider: 'anthropic', apiKey: 'sk-claude', model: 'claude-haiku-5-5' },
    ]));
    await withConfig(`${yaml()}${both}  provider: anthropic\n`, async (path) => assert.deepEqual((await loadConfig(path)).review.map(entry => entry.provider), ['anthropic', 'openai']));
    // Only one key: that provider alone, with no backup; an explicitly chosen primary must have its key.
    await withConfig(`${yaml()}review:\n  anthropic:\n    apiKey: sk-claude\n    model: claude-x\n`, async (path) => assert.deepEqual((await loadConfig(path)).review, [{ provider: 'anthropic', apiKey: 'sk-claude', model: 'claude-x' }]));
    await withConfig(`${yaml()}review:\n  provider: openai\n  anthropic:\n    apiKey: sk-claude\n`, async (path) => assert.rejects(loadConfig(path), /review\.provider is openai/));
    // The shipped example: a chosen provider with empty keys leaves the review off rather than refusing to start.
    await withConfig(`${yaml()}review:\n  provider: openai\n  openai:\n    apiKey: ''\n  anthropic:\n    apiKey: ''\n`, async (path) => assert.equal((await loadConfig(path)).review, undefined));
    await withConfig(`${yaml()}review:\n  provider: gemini\n`, async (path) => assert.rejects(loadConfig(path), /review\.provider must be/));
    // OpenAI reasoning effort: absent keeps the model default; a typo or a Claude effort is refused at startup.
    await withConfig(`${yaml()}review:\n  openai:\n    apiKey: sk-openai\n    reasoningEffort: low\n`, async (path) => assert.deepEqual((await loadConfig(path)).review, [{ provider: 'openai', apiKey: 'sk-openai', model: 'gpt-6-luna', reasoningEffort: 'low' }]));
    await withConfig(`${yaml()}review:\n  openai:\n    apiKey: sk-openai\n    reasoningEffort: fast\n`, async (path) => assert.rejects(loadConfig(path), /review\.openai\.reasoningEffort must be one of/));
    await withConfig(`${yaml()}review:\n  anthropic:\n    apiKey: sk-claude\n    reasoningEffort: low\n`, async (path) => assert.rejects(loadConfig(path), /review\.anthropic\.reasoningEffort is only supported for openai/));
    // Fast mode is opt-in per request; the timeout applies to every provider and is bounded.
    await withConfig(`${yaml()}review:\n  timeoutSeconds: 12\n  openai:\n    apiKey: sk-openai\n    serviceTier: fast\n  anthropic:\n    apiKey: sk-claude\n`, async (path) => assert.deepEqual((await loadConfig(path)).review, [
      { provider: 'openai', apiKey: 'sk-openai', model: 'gpt-6-luna', serviceTier: 'fast', timeoutMs: 12_000 },
      { provider: 'anthropic', apiKey: 'sk-claude', model: 'claude-haiku-5-5', timeoutMs: 12_000 },
    ]));
    await withConfig(`${yaml()}review:\n  openai:\n    apiKey: sk-openai\n    serviceTier: turbo\n`, async (path) => assert.rejects(loadConfig(path), /review\.openai\.serviceTier must be one of/));
    await withConfig(`${yaml()}review:\n  anthropic:\n    apiKey: sk-claude\n    serviceTier: fast\n`, async (path) => assert.rejects(loadConfig(path), /review\.anthropic\.serviceTier is only supported for openai/));
    for (const timeout of ['0', '121', '"12"', '.nan']) {
      await withConfig(`${yaml()}review:\n  timeoutSeconds: ${timeout}\n  openai:\n    apiKey: sk-openai\n`, async (path) => assert.rejects(loadConfig(path), /review\.timeoutSeconds must be/));
    }
    process.env.NEKOGUARD_OPENAI_API_KEY = 'sk-env-openai';
    process.env.NEKOGUARD_ANTHROPIC_API_KEY = 'sk-env-claude';
    await withConfig(`${yaml()}${both}`, async (path) => assert.deepEqual((await loadConfig(path)).review.map(entry => entry.apiKey), ['sk-env-openai', 'sk-env-claude']));
    process.env.NEKOGUARD_OPENAI_API_KEY = 'bad key';
    await withConfig(yaml(), async (path) => assert.rejects(loadConfig(path), (error) => /review\.openai\.apiKey/.test(error.message) && !error.message.includes('bad key')));
    delete process.env.NEKOGUARD_OPENAI_API_KEY;
    delete process.env.NEKOGUARD_ANTHROPIC_API_KEY;
    // The former single-provider names fail loudly instead of silently switching the review off.
    await withConfig(`${yaml()}review:\n  apiKey: sk-old\n`, async (path) => assert.rejects(loadConfig(path), (error) => /review\.anthropic/.test(error.message) && !error.message.includes('sk-old')));
    process.env.NEKOGUARD_REVIEW_API_KEY = 'sk-old-env';
    await withConfig(yaml(), async (path) => assert.rejects(loadConfig(path), (error) => /NEKOGUARD_ANTHROPIC_API_KEY/.test(error.message) && !error.message.includes('sk-old-env')));
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name];
    }
  }
});

test('the direct alert threshold is optional and may not sit below the scam threshold', async () => {
  await withConfig(yaml('60'), async (path) => assert.equal((await loadConfig(path)).detection.directAlertPercent, undefined));
  await withConfig(`${yaml('60')}`.replace('detection:\n', 'detection:\n  directAlertPercent: 90\n'), async (path) => assert.equal((await loadConfig(path)).detection.directAlertPercent, 90));
  await withConfig(`${yaml('60')}`.replace('detection:\n', 'detection:\n  directAlertPercent: 50\n'), async (path) => assert.rejects(loadConfig(path), /directAlertPercent/));
  await withConfig(`${yaml('60')}`.replace('detection:\n', 'detection:\n  directAlertPercent: 101\n'), async (path) => assert.rejects(loadConfig(path), /directAlertPercent/));
});
