import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAlerts } from '../dist/alerts.js';

const message = {
  messageId: '123456789', channelId: 'square-chat', channelKind: 'square',
  senderId: 'sender', senderName: 'Sender', text: 'Never copy this scam text',
  contentType: 'TEXT', createdAt: 0,
};
const admin = { userId: 'admin-1', displayName: '小貓🐱', role: 'admin' };

test('renders actual mentions with exclusive UTF-16 offsets and a source reply', () => {
  const [alert] = buildAlerts(message, { probability: 0.6999, tactic: { kind: 'investment', confidence: 0.9234 } }, [admin, { ...admin, userId: 'admin-2', displayName: '𠮷野🙂' }]);
  assert.equal(alert.replyTo, message.messageId);
  assert.match(alert.text, /訊息 ID：123456789/);
  assert.match(alert.text, /詐騙機率：69\.99%/);
  assert.match(alert.text, /投資詐騙（手法信心度 92\.34%）/);
  assert.match(alert.text, /模型估計/);
  assert.ok(!alert.text.includes(message.text));
  assert.equal(alert.text.slice(alert.mentions[0].start, alert.mentions[0].end), '@小貓🐱');
  assert.equal(alert.text.slice(alert.mentions[1].start, alert.mentions[1].end), '@𠮷野🙂');
  assert.equal(alert.mentions[0].end - alert.mentions[0].start, '@小貓🐱'.length);
  assert.equal(alert.mentions[1].start, alert.mentions[0].end + 1);
});

test('mentions every unique administrator across max-20 batches', () => {
  const admins = Array.from({ length: 47 }, (_, index) => ({
    userId: `admin-${index}`, displayName: `管理員${index}`, role: index % 2 ? 'coAdmin' : 'admin',
  }));
  const alerts = buildAlerts(message, { probability: 1 }, [...admins, admins[0], admins[30]]);
  assert.deepEqual(alerts.map((alert) => alert.mentions.length), [20, 20, 7]);
  assert.deepEqual(alerts.flatMap((alert) => alert.mentions.map((mention) => mention.userId)), admins.map((entry) => entry.userId));
  for (const alert of alerts) {
    assert.equal(alert.replyTo, message.messageId);
    assert.ok(alert.text.length <= 8000);
    assert.match(alert.text, /詐騙機率：100%/);
  }
});

test('bounds and sanitizes hostile display names without breaking surrogate pairs', () => {
  const admins = Array.from({ length: 20 }, (_, index) => ({
    userId: `admin-${index}`, displayName: '\n\u202e' + '🐱'.repeat(5000) + '\u0000', role: 'admin',
  }));
  const [alert] = buildAlerts(message, { probability: 0.7 }, admins);
  assert.ok(alert.text.length <= 8000);
  for (const mention of alert.mentions) {
    const rendered = alert.text.slice(mention.start, mention.end);
    assert.equal(rendered, '@' + '🐱'.repeat(40));
    assert.ok(!/[\u0000\u202e]/u.test(rendered));
  }
  const [fallback] = buildAlerts(message, { probability: 0 }, [{ ...admin, displayName: '\n\u202e' }]);
  assert.equal(fallback.text.slice(fallback.mentions[0].start, fallback.mentions[0].end), '@管理員');
});

test('unknown and missing tactics are reported honestly', () => {
  const [missing] = buildAlerts(message, { probability: 0.7 }, [admin]);
  assert.match(missing.text, /未提供詐騙手法及信心度/);
  const [unknown] = buildAlerts(message, { probability: 0.7, tactic: { kind: 'new-server-kind', confidence: 0.2 } }, [admin]);
  assert.match(unknown.text, /未能辨識的詐騙手法/);
  assert.match(unknown.text, /手法信心度 20%/);
  assert.ok(!unknown.text.includes('new-server-kind'));
});

test('rejects empty administrators and invalid analysis rather than implying safety', () => {
  assert.throws(() => buildAlerts(message, { probability: 0.7 }, []), /without administrators/);
  for (const probability of [NaN, Infinity, -0.01, 1.01, '0.7', undefined]) {
    assert.throws(() => buildAlerts(message, { probability }, [admin]), /Invalid scam probability/);
  }
  for (const confidence of [NaN, Infinity, -0.1, 1.1, '0.9', undefined]) {
    assert.throws(() => buildAlerts(message, { probability: 0.7, tactic: { kind: 'phishing', confidence } }, [admin]), /Invalid scam tactic/);
  }
  assert.throws(() => buildAlerts(message, { probability: 0.7, tactic: null }, [admin]), /Invalid scam tactic/);
});
