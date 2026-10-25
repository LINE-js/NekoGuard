import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';

export interface Config {
  api: { url: string; token: string };
  /** `directAlertPercent`: at or above it the admins are mentioned at once, skipping the intent review. */
  detection: { thresholdPercent: number; crownThresholdPercent: number; directAlertPercent?: number };
  /** Present only when a TypeSafe key is configured: crown checks for backends that cannot judge pictures. */
  jev?: { token: string; model: string };
  /** Present only when an Anthropic key is configured: second opinion on flagged messages. */
  review?: { apiKey: string; model: string };
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
  const thresholdPercent = percent(value.detection.thresholdPercent, 'detection.thresholdPercent');
  // Optional so existing configurations keep working; the crown check is a separate decision.
  const crownThresholdPercent = value.detection.crownThresholdPercent === undefined
    ? 70 : percent(value.detection.crownThresholdPercent, 'detection.crownThresholdPercent');
  // Optional: absent means every hit goes through the intent review when one is configured.
  const directAlertPercent = value.detection.directAlertPercent === undefined
    ? undefined : percent(value.detection.directAlertPercent, 'detection.directAlertPercent');
  if (directAlertPercent !== undefined && directAlertPercent < thresholdPercent) {
    throw new Error('detection.directAlertPercent must not be below detection.thresholdPercent.');
  }
  const jev = value.jev === undefined || value.jev === null ? {} : value.jev;
  if (!object(jev)) throw new Error('jev must be a mapping when present.');
  const jevToken = process.env.NEKOGUARD_JEV_TOKEN ?? jev.token ?? '';
  // Printable ASCII without spaces: the key goes into an HTTP header as is.
  if (typeof jevToken !== 'string' || (jevToken !== '' && !/^[\x21-\x7e]+$/.test(jevToken))) {
    throw new Error('jev.token must be printable ASCII without spaces.');
  }
  const model = jev.model ?? 'jev-1.13.0';
  if (typeof model !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(model)) throw new Error('jev.model must be a model name.');
  const review = value.review === undefined || value.review === null ? {} : value.review;
  if (!object(review)) throw new Error('review must be a mapping when present.');
  const reviewKey = process.env.NEKOGUARD_REVIEW_API_KEY ?? review.apiKey ?? '';
  if (typeof reviewKey !== 'string' || (reviewKey !== '' && !/^[\x21-\x7e]+$/.test(reviewKey))) {
    throw new Error('review.apiKey must be printable ASCII without spaces.');
  }
  const reviewModel = review.model ?? 'claude-haiku-5-5';
  if (typeof reviewModel !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(reviewModel)) throw new Error('review.model must be a model name.');
  return {
    api: { url, token },
    detection: { thresholdPercent, crownThresholdPercent, ...(directAlertPercent === undefined ? {} : { directAlertPercent }) },
    ...(jevToken ? { jev: { token: jevToken, model } } : {}),
    ...(reviewKey ? { review: { apiKey: reviewKey, model: reviewModel } } : {}),
  };
}

function percent(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error(`${name} must be a finite number between 0 and 100.`);
  }
  return value;
}
