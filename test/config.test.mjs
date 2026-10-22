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
