import { describe, expect, test } from 'bun:test';
import { createPasskey, createPassword, hashMatrixHex } from '../src/index';

const matrix = [
  [2, 2.3, 4],
  [7, 7.8, 7],
  [4.442, 3, 9]
] as const;

const expectedPassword24 = 'o5{?x!n_i=X^STJ2Sy/-1UUI';
const expectedPassword16 = 'o5{?x!n_i=X^STJ2';
const expectedPasskeyPrivateHex =
  '2e81d3e6aee66dc4735c051dbee13ea63e215f309259d5eedf0d7951e31e29bb';
const expectedMatrixHashHex =
  '005664ca9e58313a597e8e2ab6b1c510f27087d5f8b5b033576c7d8c9088fda5';

describe('deterministic derivation', () => {
  test('createPassword matches expected output', () => {
    expect(createPassword(matrix, { length: 24 })).toBe(expectedPassword24);
    expect(createPassword(matrix, { length: 16 })).toBe(expectedPassword16);
  });

  test('createPasskey exposes deterministic private key', () => {
    const passkey = createPasskey(matrix);
    expect(passkey.privateKeyHex).toBe(expectedPasskeyPrivateHex);
    expect(passkey.publicKey.length).toBe(32);
    expect(passkey.publicKeyHex).toHaveLength(64);
  });

  test('hashMatrixHex matches expected hash', () => {
    expect(hashMatrixHex(matrix)).toBe(expectedMatrixHashHex);
  });
});

describe('options and validation', () => {
  test('salt changes the output', () => {
    const base = createPassword(matrix, { length: 24 });
    const salted = createPassword(matrix, { length: 24, salt: 'salt' });
    expect(salted).not.toBe(base);
  });

  test('custom alphabet is respected', () => {
    const alphabet = 'abc';
    const password = createPassword(matrix, { length: 64, alphabet });
    for (const char of password) {
      expect(alphabet.includes(char)).toBe(true);
    }
  });

  test('invalid inputs throw', () => {
    expect(() => createPassword([[1, Number.NaN]])).toThrow();
    expect(() => createPassword(matrix, { length: 0 })).toThrow();
    expect(() => createPassword(matrix, { alphabet: 'a' })).toThrow();
  });
});
