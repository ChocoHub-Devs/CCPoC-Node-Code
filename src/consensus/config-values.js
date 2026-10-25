'use strict';

const DEFAULT_MAX_SUPPLY = '21000000000000000000000000';

function normalizeMaxSupply(value = DEFAULT_MAX_SUPPLY) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new Error('maxSupply must be an exact positive decimal string, not an unsafe JSON number. Set "maxSupply": "21000000000000000000000000" for the default network; existing databases must match the configured genesis.');
  }
  if (!['string', 'number', 'bigint'].includes(typeof value)) {
    throw new Error('maxSupply must be an exact positive decimal string');
  }
  const decimal = String(value);
  if (!/^[1-9][0-9]*$/.test(decimal)) {
    throw new Error('maxSupply must be a canonical positive decimal integer; scientific notation is not supported');
  }
  return decimal;
}

module.exports = { DEFAULT_MAX_SUPPLY, normalizeMaxSupply };
