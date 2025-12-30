# Deterministic Passkeys

Deterministic passwords and ed25519 passkeys derived from a multidimensional array of floats.

## Install

```bash
npm install @siguiente/deterministic
```

## Usage

```ts
import {
  createPassword,
  createPasskey,
  expandMatrixBytes,
  hashMatrixHex
} from '@siguiente/deterministic';

const matrix = [
  [2, 2.3, 4],
  [7, 7.8, 7],
  [4.442, 3, 9]
];

const password = createPassword(matrix, { length: 16 });
const passkey = createPasskey(matrix, { info: 'device-a' });
const digest = hashMatrixHex(matrix, { info: 'audit' });
const bytes = expandMatrixBytes(matrix, 64, { salt: 'session' });

console.log(password);
console.log(passkey.publicKeyHex);
console.log(digest);
console.log(bytes.length);
```

## Notes

- The matrix is encoded as big-endian float64 values with row length prefixes for deterministic hashing.
- Non-finite values (NaN, Infinity) throw.
- Use `salt` and `info` options to domain-separate different use cases.
- Passwords are generated deterministically and must include lowercase, uppercase, numeric, and symbol characters.
