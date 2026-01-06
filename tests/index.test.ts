import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, test } from 'bun:test';
import { createPasskey, createPassword, hashMatrixHex } from '../src/index';
import { azimuthPitchRollMatrix, baseMatrix, positionLatLongPairs, positionMatrix } from './fixtures';

const expectedPassword16 = 'o5{?x!n_i=X^STJ2';
const expectedAzimuthPassword16 = '_k$3%-8jGA{8&Dfv';
const expectedPositionPassword16 = '2MY?K(,/5@wg2@9p';
const expectedPasskeyPrivateHex =
  '2e81d3e6aee66dc4735c051dbee13ea63e215f309259d5eedf0d7951e31e29bb';
const expectedMatrixHashHex =
  '005664ca9e58313a597e8e2ab6b1c510f27087d5f8b5b033576c7d8c9088fda5';
const expectedPositionHashHex =
  '345e42db0fa1a5f1d7e8c3f5ca7cbfdaf69a8df8a2548fc9f7b59fa9ab828d14';
const expectedSignatureHex =
  '54726f95921804d43b129f1220f3406e2aa09968388a5f93e1b2a873dbacd7a65d5f99fdfd784eeff80b7f9a5eab781b5f597aab2e90a016a237a75f6626900e';

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

  test('position matrix stays aligned with latitude/longitude pairs', () => {
    expect(createPassword(positionMatrix, { length: 16 })).toBe(
      expectedPositionPassword16
    );
    expect(hashMatrixHex(positionMatrix)).toBe(expectedPositionHashHex);

    // rows should allow different lengths (angles vs lat/long pairs)
    const rowLengths = positionMatrix.map((row) => row.length);
    expect(new Set(rowLengths).size).toBeGreaterThan(1);

    for (const { rowIndex, latitude, longitude } of positionLatLongPairs) {
      const row = positionMatrix[rowIndex];
      expect(row).toBeDefined();
      expect(row.length).toBe(2);
      expect(row[0]).toBe(latitude);
      expect(row[1]).toBe(longitude);
      expect(latitude).toBeGreaterThanOrEqual(-90);
      expect(latitude).toBeLessThanOrEqual(90);
      expect(longitude).toBeGreaterThanOrEqual(-180);
      expect(longitude).toBeLessThanOrEqual(180);
    }
  });

  test('signatures are deterministic with and without extraEntropy', () => {
    const message = utf8ToBytes('deterministic-signature');
    const passkey = createPasskey(baseMatrix);

    const signature = ed25519.sign(message, passkey.privateKey);
    const signatureAgain = ed25519.sign(message, passkey.privateKey);

    expect(bytesToHex(signatureAgain)).toBe(bytesToHex(signature));
    expect(bytesToHex(signature)).toBe(expectedSignatureHex);

    const extraEntropy = new Uint8Array(32).fill(7);
    const signatureWithEntropy = ed25519.sign(message, passkey.privateKey, {
      extraEntropy
    });
    const signatureWithEntropyAgain = ed25519.sign(message, passkey.privateKey, {
      extraEntropy
    });

    expect(bytesToHex(signatureWithEntropyAgain)).toBe(
      bytesToHex(signatureWithEntropy)
    );
    expect(bytesToHex(signatureWithEntropy)).toBe(expectedSignatureHex);
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
