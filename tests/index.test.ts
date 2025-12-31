import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, test } from 'bun:test';
import {
  createPasskey,
  createPassword,
  createSharedPasskey,
  createSharedSignature,
  hashMatrixHex,
  signMessage,
  verifyMessageSignature,
  verifySharedSignatures
} from '../src/index';
import { azimuthPitchRollMatrix, baseMatrix } from './fixtures';

const expectedPassword16 = 'o5{?x!n_i=X^STJ2';
const expectedAzimuthPassword16 = '_k$3%-8jGA{8&Dfv';
const expectedPasskeyPrivateHex =
  '2e81d3e6aee66dc4735c051dbee13ea63e215f309259d5eedf0d7951e31e29bb';
const expectedMatrixHashHex =
  '005664ca9e58313a597e8e2ab6b1c510f27087d5f8b5b033576c7d8c9088fda5';
const expectedSignatureHex =
  '54726f95921804d43b129f1220f3406e2aa09968388a5f93e1b2a873dbacd7a65d5f99fdfd784eeff80b7f9a5eab781b5f597aab2e90a016a237a75f6626900e';
const expectedMessageSignatureHex =
  'ce0a6545d1931b36c2992936ee3abc2aedb153df10c493bf17286850d063a1b2f9d908c0c482924df5b0d0e5d3a471e17ca809df084bb6e5f79a57c178ccd204';
const expectedSharedSignatureHexes = [
  '76fbc196016e947c7f8aa7c47d2b48d91aef159d1562bdbe2feb9a5a7d7cd03d054d1fc56e29b4cec27ce09c6e751e2a25111b4dce0d5705dd92dfd0fd353604',
  '8f1843162d7c6bfed5b7cd5e80161c1762b4c33cf28d2b251eace1c07247390d2fdf3356c9ac4cefb14f787b414d6345e431eb73145eae33bd04182f60299000'
];

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

  test('signMessage produces deterministic signatures', () => {
    const message = 'mensaje deterministico';
    const signature = signMessage(baseMatrix, message);

    expect(signature.signatureHex).toBe(expectedMessageSignatureHex);
    expect(verifyMessageSignature(message, signature.signature, signature.publicKey)).toBe(
      true
    );
  });

  test('shared signatures are deterministic across matrices', () => {
    const message = 'mensaje compartido';
    const sharedSignature = createSharedSignature(
      [baseMatrix, azimuthPitchRollMatrix],
      message
    );
    const sharedPasskeys = createSharedPasskey([
      baseMatrix,
      azimuthPitchRollMatrix
    ]);

    expect(sharedSignature.signatures).toHaveLength(2);
    expect(sharedSignature.signatures[0]?.signatureHex).toBe(
      expectedSharedSignatureHexes[0]
    );
    expect(sharedSignature.signatures[1]?.signatureHex).toBe(
      expectedSharedSignatureHexes[1]
    );
    expect(
      verifySharedSignatures(message, sharedSignature)
    ).toBe(true);
    expect(sharedSignature.signatures[0]?.publicKeyHex).toBe(
      sharedPasskeys[0]?.publicKeyHex
    );
    expect(sharedSignature.signatures[1]?.publicKeyHex).toBe(
      sharedPasskeys[1]?.publicKeyHex
    );
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
