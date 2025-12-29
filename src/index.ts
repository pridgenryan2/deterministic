import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export type FloatMatrix = readonly (readonly number[])[];

export interface DeriveOptions {
  salt?: string | Uint8Array;
  info?: string;
}

export interface PasswordOptions extends DeriveOptions {
  length?: number;
  alphabet?: string;
}

export interface PasskeyOptions extends DeriveOptions {}

export interface Passkey {
  curve: 'ed25519';
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
  publicKeyHex: string;
}

const DOMAIN_TAG = utf8ToBytes('clave:deterministic:v1');
const PURPOSE_PASSWORD = utf8ToBytes('password');
const PURPOSE_PASSKEY = utf8ToBytes('passkey');
const PURPOSE_HASH = utf8ToBytes('hash');
const DEFAULT_ALPHABET =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/';

function toBytes(value: string | Uint8Array): Uint8Array {
  return typeof value === 'string' ? utf8ToBytes(value) : value;
}

function assertMatrix(matrix: FloatMatrix): void {
  if (!Array.isArray(matrix)) {
    throw new TypeError('matrix must be an array of number arrays');
  }
  for (const row of matrix) {
    if (!Array.isArray(row)) {
      throw new TypeError('matrix must be an array of number arrays');
    }
    for (const value of row) {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new TypeError('matrix values must be finite numbers');
      }
    }
  }
}

function encodeFloatMatrix(matrix: FloatMatrix): Uint8Array {
  assertMatrix(matrix);
  let totalBytes = 4;
  for (const row of matrix) {
    totalBytes += 4 + row.length * 8;
  }
  const buffer = new ArrayBuffer(totalBytes);
  const view = new DataView(buffer);
  let offset = 0;
  view.setUint32(offset, matrix.length, false);
  offset += 4;
  for (const row of matrix) {
    view.setUint32(offset, row.length, false);
    offset += 4;
    for (const value of row) {
      view.setFloat64(offset, value, false);
      offset += 8;
    }
  }
  return new Uint8Array(buffer);
}

function deriveSeed(
  matrix: FloatMatrix,
  purpose: Uint8Array,
  options?: DeriveOptions
): Uint8Array {
  const data = encodeFloatMatrix(matrix);
  const salt = options?.salt ? toBytes(options.salt) : new Uint8Array(0);
  const info = options?.info ? utf8ToBytes(options.info) : new Uint8Array(0);
  return sha256(concatBytes(DOMAIN_TAG, purpose, salt, info, data));
}

function expandBytes(seed: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);
    const block = sha256(concatBytes(seed, counterBytes));
    const chunk = Math.min(block.length, length - offset);
    out.set(block.subarray(0, chunk), offset);
    offset += chunk;
    counter += 1;
  }
  return out;
}

export function createPassword(
  matrix: FloatMatrix,
  options: PasswordOptions = {}
): string {
  const length = options.length ?? 16;
  if (!Number.isInteger(length) || length < 8 || length > 16) {
    throw new RangeError('password length must be between 8 and 16');
  }
  const alphabet = options.alphabet ?? DEFAULT_ALPHABET;
  if (alphabet.length < 2 || alphabet.length > 256) {
    throw new RangeError('alphabet length must be between 2 and 256');
  }
  if (
    !/[a-z]/.test(alphabet) ||
    !/[A-Z]/.test(alphabet) ||
    !/[0-9]/.test(alphabet) ||
    !/[^a-zA-Z0-9]/.test(alphabet)
  ) {
    throw new RangeError(
      'alphabet must include lowercase, uppercase, numeric, and symbol characters'
    );
  }

  const seed = deriveSeed(matrix, PURPOSE_PASSWORD, options);
  const max = Math.floor(256 / alphabet.length) * alphabet.length;
  const isValidPassword = (value: string) =>
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    /[^a-zA-Z0-9]/.test(value);

  for (let attempt = 0; attempt < 1000; attempt += 1) {
    let password = '';
    let counter = attempt;
    let pool = new Uint8Array(0);
    let poolIndex = 0;

    while (password.length < length) {
      if (poolIndex >= pool.length) {
        const counterBytes = new Uint8Array(4);
        new DataView(counterBytes.buffer).setUint32(0, counter, false);
        pool = sha256(concatBytes(seed, counterBytes));
        poolIndex = 0;
        counter += 1;
      }
      const byte = pool[poolIndex];
      poolIndex += 1;
      if (byte >= max) {
        continue;
      }
      password += alphabet[byte % alphabet.length];
    }

    if (isValidPassword(password)) {
      return password;
    }
  }

  throw new Error('failed to generate a password meeting complexity rules');
}

export function createPasskey(
  matrix: FloatMatrix,
  options: PasskeyOptions = {}
): Passkey {
  const privateKey = deriveSeed(matrix, PURPOSE_PASSKEY, options);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    curve: 'ed25519',
    privateKey,
    publicKey,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey)
  };
}

export function hashMatrix(matrix: FloatMatrix, options: DeriveOptions = {}): Uint8Array {
  return deriveSeed(matrix, PURPOSE_HASH, options);
}

export function hashMatrixHex(matrix: FloatMatrix, options: DeriveOptions = {}): string {
  return bytesToHex(hashMatrix(matrix, options));
}
