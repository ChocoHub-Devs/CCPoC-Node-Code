'use strict';

/**
 * Return whether two positive integer values differ by at most maxRatio.
 * Multiplicative comparisons avoid truncation from BigInt division, which can
 * otherwise accept ratios slightly above the configured limit.
 */
function isWithinRatio(candidate, expected, maxRatio = 2n) {
  let candidateInt;
  let expectedInt;
  let maxRatioInt;

  try {
    candidateInt = BigInt(candidate);
    expectedInt = BigInt(expected);
    maxRatioInt = BigInt(maxRatio);
  } catch {
    return false;
  }

  if (candidateInt <= 0n || expectedInt <= 0n || maxRatioInt < 1n) {
    return false;
  }

  return candidateInt <= expectedInt * maxRatioInt
    && expectedInt <= candidateInt * maxRatioInt;
}

module.exports = { isWithinRatio };
