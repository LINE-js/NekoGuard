import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';
import type { ReasoningEffort, ServiceTier } from './review.js';

export interface Config {
  api: { url: string; token: string };
  /** `directAlertPercent`: at or above it the admins are mentioned at once, skipping the intent review. */
  detection: { thresholdPercent: number; crownThresholdPercent: number; directAlertPercent?: number };
  /** Present only when a TypeSafe key is configured: crown checks for backends that cannot judge pictures. */
  jev?: { token: string; model: string };
  /** Intent reviewers in call order: the configured primary first, then the backup. Absent without any key. */
  review?: ReviewerConfig[];
}

export interface ReviewerConfig {
  provider: 'openai' | 'anthropic';
  apiKey: string;
  model: string;
  /** OpenAI only; absent means the model's default. */
  reasoningEffort?: ReasoningEffort;
  /** OpenAI only; absent means the project's service tier. */
  serviceTier?: ServiceTier;
  /** Per request; absent means 30 seconds. */
  timeoutMs?: number;
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
  // Former single-provider names would otherwise be ignored silently and switch the review off.
  if (review.apiKey !== undefined || review.model !== undefined) {
    throw new Error('review.apiKey and review.model moved to review.anthropic or review.openai; see config.example.yaml.');
  }
  if (process.env.NEKOGUARD_REVIEW_API_KEY !== undefined) {
    throw new Error('NEKOGUARD_REVIEW_API_KEY was replaced by NEKOGUARD_ANTHROPIC_API_KEY and NEKOGUARD_OPENAI_API_KEY.');
  }
  const primary = review.provider ?? 'openai';
  if (primary !== 'openai' && primary !== 'anthropic') throw new Error('review.provider must be openai or anthropic.');
  const openai = reviewer(review, 'openai', 'NEKOGUARD_OPENAI_API_KEY', 'gpt-6-luna');
  const anthropic = reviewer(review, 'anthropic', 'NEKOGUARD_ANTHROPIC_API_KEY', 'claude-haiku-5-5');
  // With no key at all the review is simply off (the shipped example); a backup-only setup is a mistake.
  if (review.provider !== undefined && (openai || anthropic) && !(primary === 'openai' ? openai : anthropic)) {
    throw new Error(`review.provider is ${primary} but no ${primary} API key is configured.`);
  }
  const timeoutSeconds = review.timeoutSeconds;
  if (timeoutSeconds !== undefined && (typeof timeoutSeconds !== 'number' || !Number.isFinite(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 120)) {
    throw new Error('review.timeoutSeconds must be a number between 1 and 120.');
  }
  const reviewers = (primary === 'openai' ? [openai, anthropic] : [anthropic, openai])
    .filter((entry): entry is ReviewerConfig => entry !== undefined)
    .map(entry => timeoutSeconds === undefined ? entry : { ...entry, timeoutMs: timeoutSeconds * 1000 });
  return {
    api: { url, token },
    detection: { thresholdPercent, crownThresholdPercent, ...(directAlertPercent === undefined ? {} : { directAlertPercent }) },
    ...(jevToken ? { jev: { token: jevToken, model } } : {}),
    ...(reviewers.length > 0 ? { review: reviewers } : {}),
  };
}

const REASONING_EFFORTS: readonly ReasoningEffort[] = ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'];
const SERVICE_TIERS: readonly ServiceTier[] = ['auto', 'default', 'flex', 'scale', 'priority', 'fast', 'ultrafast'];

/** One provider's key (environment first) and model; undefined when no key is configured. */
function reviewer(review: Record<string, unknown>, provider: ReviewerConfig['provider'], envName: string, defaultModel: string): ReviewerConfig | undefined {
  const section = review[provider] === undefined || review[provider] === null ? {} : review[provider];
  if (!object(section)) throw new Error(`review.${provider} must be a mapping when present.`);
  const apiKey = process.env[envName] ?? section.apiKey ?? '';
  // Printable ASCII without spaces: the key goes into an HTTP header as is.
  if (typeof apiKey !== 'string' || (apiKey !== '' && !/^[\x21-\x7e]+$/.test(apiKey))) {
    throw new Error(`review.${provider}.apiKey must be printable ASCII without spaces.`);
  }
  const model = section.model ?? defaultModel;
  if (typeof model !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(model)) throw new Error(`review.${provider}.model must be a model name.`);
  const reasoningEffort = openaiChoice(section, provider, 'reasoningEffort', REASONING_EFFORTS);
  const serviceTier = openaiChoice(section, provider, 'serviceTier', SERVICE_TIERS);
  if (!apiKey) return undefined;
  return { provider, apiKey, model, ...(reasoningEffort ? { reasoningEffort } : {}), ...(serviceTier ? { serviceTier } : {}) };
}

/** An OpenAI-only option from a fixed list; undefined when absent. Typos are refused, not sent to the API. */
function openaiChoice<T extends string>(section: Record<string, unknown>, provider: ReviewerConfig['provider'], key: string, allowed: readonly T[]): T | undefined {
  const value = section[key];
  if (value === undefined || value === null) return undefined;
  if (provider !== 'openai') throw new Error(`review.${provider}.${key} is only supported for openai.`);
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw new Error(`review.openai.${key} must be one of ${allowed.join(', ')}.`);
  return value as T;
}

function percent(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error(`${name} must be a finite number between 0 and 100.`);
  }
  return value;
}
