import { describe, expect, test } from 'bun:test';
import { createPasskey, createPassword, hashMatrixHex } from '../src/index';
import { azimuthPitchRollMatrix, baseMatrix } from './fixtures';

const expectedPassword16 = 'o5{?x!n_i=X^STJ2';
const expectedAzimuthPassword16 = '_k$3%-8jGA{8&Dfv';
const expectedPasskeyPrivateHex =
  '2e81d3e6aee66dc4735c051dbee13ea63e215f309259d5eedf0d7951e31e29bb';
const expectedMatrixHashHex =
  '005664ca9e58313a597e8e2ab6b1c510f27087d5f8b5b033576c7d8c9088fda5';

describe('deterministic derivation', () => {
  test('createPassword matches expected output', () => {
    expect(createPassword(baseMatrix, { length: 16 })).toBe(expectedPassword16);
    expect(createPassword(azimuthPitchRollMatrix, { length: 16 })).toBe(
      expectedAzimuthPassword16
    );
  });

  test('createPasskey exposes deterministic private key', () => {
    const passkey = createPasskey(baseMatrix);
    expect(passkey.privateKeyHex).toBe(expectedPasskeyPrivateHex);
    expect(passkey.publicKey.length).toBe(32);
    expect(passkey.publicKeyHex).toHaveLength(64);
  });

  test('hashMatrixHex matches expected hash', () => {
    expect(hashMatrixHex(baseMatrix)).toBe(expectedMatrixHashHex);
  });
});

describe('options and validation', () => {
  test('salt changes the output', () => {
    const base = createPassword(baseMatrix, { length: 16 });
    const salted = createPassword(baseMatrix, { length: 16, salt: 'salt' });
    expect(salted).not.toBe(base);
  });

  test('custom alphabet is respected', () => {
    const alphabet = 'abAB12!@';
    const password = createPassword(baseMatrix, { length: 12, alphabet });
    for (const char of password) {
      expect(alphabet.includes(char)).toBe(true);
    }
  });

  test('invalid inputs throw', () => {
    expect(() => createPassword([[1, Number.NaN]])).toThrow();
    expect(() => createPassword(baseMatrix, { length: 0 })).toThrow();
    expect(() => createPassword(baseMatrix, { length: 17 })).toThrow();
    expect(() => createPassword(baseMatrix, { alphabet: 'a' })).toThrow();
    expect(() => createPassword(baseMatrix, { alphabet: 'abc123' })).toThrow();
  });
});
