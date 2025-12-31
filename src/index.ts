import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * A rectangular (or ragged) matrix of finite floating-point numbers.
 *
 * Values are encoded as big-endian float64 data with row-length prefixes to ensure
 * deterministic hashing across platforms.
 */
export type FloatMatrix = readonly (readonly number[])[];

/**
 * Shared options for deterministic derivations.
 */
export interface DeriveOptions {
  /** Additional salt bytes to domain-separate inputs. */
  salt?: string | Uint8Array;
  /** Additional context to separate uses of the same matrix. */
  info?: string;
}

/**
 * Options for creating deterministic passwords.
 */
export interface PasswordOptions extends DeriveOptions {
  /**
   * Desired length. Defaults to 16. Must be between 8 and 16 inclusive to satisfy
   * password complexity requirements.
   */
  length?: number;
  /**
   * Characters to sample from. Must include lowercase, uppercase, digits, and symbols.
   */
  alphabet?: string;
}

/**
 * Options for creating deterministic passkeys.
 */
export interface PasskeyOptions extends DeriveOptions {}

/**
 * A deterministic Ed25519 passkey pair derived from the matrix.
 */
export interface Passkey {
  curve: "ed25519";
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
  publicKeyHex: string;
}

/**
 * A message that can be signed or verified.
 */
export type MessageInput = string | Uint8Array;

/**
 * Result of signing a message.
 */
export interface MessageSignature {
  signature: Uint8Array;
  signatureHex: string;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

/**
 * A collection of signatures that together authorize a message.
 */
export interface SharedSignatures {
  signatures: MessageSignature[];
}

const DOMAIN_TAG = utf8ToBytes("clave:deterministic:v1");
const PURPOSE_PASSWORD = utf8ToBytes("password");
const PURPOSE_PASSKEY = utf8ToBytes("passkey");
const PURPOSE_SHARED_PASSKEY = utf8ToBytes("shared-passkey");
const PURPOSE_SIGNATURE = utf8ToBytes("signature");
const PURPOSE_SHARED_SIGNATURE = utf8ToBytes("shared-signature");
const PURPOSE_HASH = utf8ToBytes("hash");
const DEFAULT_ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/";

function toBytes(value: string | Uint8Array): Uint8Array {
  return typeof value === "string" ? utf8ToBytes(value) : value;
}

function toMessageBytes(message: MessageInput): Uint8Array {
  return typeof message === "string" ? utf8ToBytes(message) : message;
}

function assertMatrix(matrix: FloatMatrix): void {
  if (!Array.isArray(matrix)) {
    throw new TypeError("matrix must be an array of number arrays");
  }
  for (const row of matrix) {
    if (!Array.isArray(row)) {
      throw new TypeError("matrix must be an array of number arrays");
    }
    for (const value of row) {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new TypeError("matrix values must be finite numbers");
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

function deriveSharedSeed(
  matrix: FloatMatrix,
  index: number,
  total: number,
  purpose: Uint8Array,
  options?: DeriveOptions
): Uint8Array {
  if (!Number.isInteger(index) || index < 0) {
    throw new RangeError("index must be a non-negative integer");
  }
  if (!Number.isInteger(total) || total <= 1) {
    throw new RangeError("total must be an integer greater than 1");
  }
  if (index >= total) {
    throw new RangeError("index must be less than total");
  }
  const indexBytes = new Uint8Array(4);
  const totalBytes = new Uint8Array(4);
  new DataView(indexBytes.buffer).setUint32(0, index, false);
  new DataView(totalBytes.buffer).setUint32(0, total, false);
  const data = encodeFloatMatrix(matrix);
  const salt = options?.salt ? toBytes(options.salt) : new Uint8Array(0);
  const info = options?.info ? utf8ToBytes(options.info) : new Uint8Array(0);
  return sha256(
    concatBytes(DOMAIN_TAG, purpose, indexBytes, totalBytes, salt, info, data)
  );
}

function assertSharedMatrices(
  matrices: readonly FloatMatrix[],
  label: string
): void {
  if (!Array.isArray(matrices) || matrices.length < 2) {
    throw new RangeError(`${label} requires at least two matrices`);
  }
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

/**
 * Deterministically derive a password that meets basic complexity requirements.
 */
export function createPassword(
  matrix: FloatMatrix,
  options: PasswordOptions = {}
): string {
  const length = options.length ?? 16;
  if (!Number.isInteger(length) || length < 8 || length > 16) {
    throw new RangeError("password length must be between 8 and 16");
  }
  const alphabet = options.alphabet ?? DEFAULT_ALPHABET;
  if (alphabet.length < 2 || alphabet.length > 256) {
    throw new RangeError("alphabet length must be between 2 and 256");
  }
  if (
    !/[a-z]/.test(alphabet) ||
    !/[A-Z]/.test(alphabet) ||
    !/[0-9]/.test(alphabet) ||
    !/[^a-zA-Z0-9]/.test(alphabet)
  ) {
    throw new RangeError(
      "alphabet must include lowercase, uppercase, numeric, and symbol characters"
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
    let password = "";
    let counter = attempt;
    let pool = new Uint8Array(0);
    let poolIndex = 0;

    while (password.length < length) {
      if (poolIndex >= pool.length) {
        const counterBytes = new Uint8Array(4);
        new DataView(counterBytes.buffer).setUint32(0, counter, false);
        pool = new Uint8Array(sha256(concatBytes(seed, counterBytes)));
        poolIndex = 0;
        counter += 1;
      }
      const byte = pool[poolIndex]!;
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

  throw new Error("failed to generate a password meeting complexity rules");
}

/**
 * Deterministically derive an Ed25519 passkey pair from the matrix.
 */
export function createPasskey(
  matrix: FloatMatrix,
  options: PasskeyOptions = {}
): Passkey {
  const privateKey = deriveSeed(matrix, PURPOSE_PASSKEY, options);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    curve: "ed25519",
    privateKey,
    publicKey,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey)
  };
}

/**
 * Deterministically derive shared Ed25519 passkeys from multiple matrices.
 */
export function createSharedPasskey(
  matrices: readonly FloatMatrix[],
  options: PasskeyOptions = {}
): Passkey[] {
  assertSharedMatrices(matrices, "createSharedPasskey");
  const total = matrices.length;
  return matrices.map((matrix, index) => {
    const privateKey = deriveSharedSeed(
      matrix,
      index,
      total,
      PURPOSE_SHARED_PASSKEY,
      options
    );
    const publicKey = ed25519.getPublicKey(privateKey);
    return {
      curve: "ed25519",
      privateKey,
      publicKey,
      privateKeyHex: bytesToHex(privateKey),
      publicKeyHex: bytesToHex(publicKey)
    };
  });
}

/**
 * Sign a message deterministically using a matrix-derived passkey.
 */
export function signMessage(
  matrix: FloatMatrix,
  message: MessageInput,
  options: DeriveOptions = {}
): MessageSignature {
  const messageBytes = toMessageBytes(message);
  const privateKey = deriveSeed(matrix, PURPOSE_SIGNATURE, options);
  const publicKey = ed25519.getPublicKey(privateKey);
  const signature = ed25519.sign(messageBytes, privateKey);
  return {
    signature,
    signatureHex: bytesToHex(signature),
    publicKey,
    publicKeyHex: bytesToHex(publicKey)
  };
}

/**
 * Sign a message deterministically using a shared matrix-derived passkey.
 */
export function createSharedSignature(
  matrices: readonly FloatMatrix[],
  message: MessageInput,
  options: DeriveOptions = {}
): SharedSignatures {
  assertSharedMatrices(matrices, "createSharedSignature");
  const messageBytes = toMessageBytes(message);
  return {
    signatures: matrices.map((matrix, index) => {
      const privateKey = deriveSharedSeed(
        matrix,
        index,
        matrices.length,
        PURPOSE_SHARED_SIGNATURE,
        options
      );
      const publicKey = ed25519.getPublicKey(privateKey);
      const signature = ed25519.sign(messageBytes, privateKey);
      return {
        signature,
        signatureHex: bytesToHex(signature),
        publicKey,
        publicKeyHex: bytesToHex(publicKey)
      };
    })
  };
}

/**
 * Verify a message signature with a provided public key.
 */
export function verifyMessageSignature(
  message: MessageInput,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return ed25519.verify(signature, toMessageBytes(message), publicKey);
}

/**
 * Verify that every signature in a shared set is valid for the message.
 */
export function verifySharedSignatures(
  message: MessageInput,
  signatures: SharedSignatures
): boolean {
  return signatures.signatures.every((entry) =>
    ed25519.verify(entry.signature, toMessageBytes(message), entry.publicKey)
  );
}

/**
 * Hash the matrix into a 32-byte SHA-256 digest for custom derivations.
 */
export function hashMatrix(
  matrix: FloatMatrix,
  options: DeriveOptions = {}
): Uint8Array {
  return deriveSeed(matrix, PURPOSE_HASH, options);
}

/**
 * Hash the matrix into a hex-encoded SHA-256 digest.
 */
export function hashMatrixHex(
  matrix: FloatMatrix,
  options: DeriveOptions = {}
): string {
  return bytesToHex(hashMatrix(matrix, options));
}

/**
 * Expand a matrix-derived seed into arbitrary-length bytes for advanced use cases.
 */
export function expandMatrixBytes(
  matrix: FloatMatrix,
  length: number,
  options: DeriveOptions = {}
): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError("length must be a positive integer");
  }
  const seed = deriveSeed(matrix, PURPOSE_HASH, options);
  return expandBytes(seed, length);
}
