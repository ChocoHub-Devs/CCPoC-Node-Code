'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isWithinRatio } = require('../src/consensus/base-target-validation');

test('accepts the configured ratio boundary in either direction', () => {
  assert.equal(isWithinRatio(20n, 10n, 2n), true);
  assert.equal(isWithinRatio(10n, 20n, 2n), true);
  assert.equal(isWithinRatio(10n, 10n, 2n), true);
});

test('rejects ratios above the boundary without integer-division truncation', () => {
  // The old 29n / 10n > 2n check evaluates to false, incorrectly accepting 2.9x.
  assert.equal(isWithinRatio(21n, 10n, 2n), false);
  assert.equal(isWithinRatio(29n, 10n, 2n), false);
  assert.equal(isWithinRatio(10n, 21n, 2n), false);
  assert.equal(isWithinRatio(10n, 29n, 2n), false);
});

test('rejects invalid or non-positive consensus values', () => {
  assert.equal(isWithinRatio(0n, 10n, 2n), false);
  assert.equal(isWithinRatio(10n, 0n, 2n), false);
  assert.equal(isWithinRatio(-1n, 10n, 2n), false);
  assert.equal(isWithinRatio(10n, 10n, 0n), false);
  assert.equal(isWithinRatio('not-a-number', 10n, 2n), false);
});
