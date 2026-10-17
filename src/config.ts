import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';

export interface Config {
  api: { url: string; token: string };
  detection: { thresholdPercent: number };
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function loadConfig(path = 'config.yaml'): Promise<Config> {
  let source: string;
  try {
    source = await readFile(path, 'utf8');
  } catch {
    throw new Error('Unable to read configuration file.');
  }
  let value: unknown;
  try {
    value = parse(source);
  } catch {
    // YAML parser diagnostics can include the credential-bearing source line.
    throw new Error('Configuration must contain valid YAML.');
  }
  if (!object(value) || !object(value.api) || !object(value.detection)) {
    throw new Error('Configuration requires api and detection sections.');
  }
  const url = value.api.url;
  if (typeof url !== 'string') {
    throw new Error('api.url must be a WebSocket /api/ws URL.');
  }
  let endpoint: URL;
  try {
    endpoint = new URL(url);
  } catch {
    throw new Error('api.url must be a WebSocket /api/ws URL.');
  }
  if (
    (endpoint.protocol !== 'ws:' && endpoint.protocol !== 'wss:') ||
    endpoint.pathname !== '/api/ws' || endpoint.username !== '' || endpoint.password !== '' ||
    url.includes('?') || url.includes('#') || url !== url.trim()
  ) {
    throw new Error('api.url must use ws or wss with exactly /api/ws and no credentials, query, or fragment.');
  }
  if (
    endpoint.protocol === 'ws:' &&
    !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)
  ) {
    throw new Error('Non-loopback api.url endpoints require wss.');
  }
  const token = process.env.NEKOGUARD_API_TOKEN ?? value.api.token;
  if (typeof token !== 'string' || token.trim() === '' || /[\u0000-\u001f\u007f]/u.test(token)) {
    throw new Error('A non-empty API token is required in NEKOGUARD_API_TOKEN or api.token.');
  }
  const thresholdPercent = value.detection.thresholdPercent;
  if (typeof thresholdPercent !== 'number' || !Number.isFinite(thresholdPercent) || thresholdPercent < 0 || thresholdPercent > 100) {
    throw new Error('detection.thresholdPercent must be a finite number between 0 and 100.');
  }
  return { api: { url, token }, detection: { thresholdPercent } };
}
