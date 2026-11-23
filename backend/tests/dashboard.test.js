const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';
process.env.DB_PATH = ':memory:';
process.env.JWT_SECRET = 'test-secret';
process.env.ENC_KEY = 'test-enc-key-32-bytes-long!!';

const { dashboardStats } = require('../server.js');

test('dashboardStats calculates totals and monthly sent counts', () => {
  const stats = dashboardStats(1);
  assert.equal(typeof stats.totalTemplates, 'number');
  assert.equal(typeof stats.avgOpenRate, 'number');
  assert.equal(typeof stats.sentThisMonth, 'number');
  assert.equal(typeof stats.totalSent, 'number');
  assert.equal(typeof stats.replies, 'number');
  assert.ok(stats.totalTemplates >= 0);
  assert.ok(stats.avgOpenRate >= 0 && stats.avgOpenRate <= 100);
  assert.ok(stats.sentThisMonth >= 0);
  assert.ok(stats.totalSent >= 0);
  assert.ok(stats.replies >= 0);
});
