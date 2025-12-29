# Deterministic Passkeys

Deterministic passwords and ed25519 passkeys derived from a multidimensional array of floats.

## Install

```bash
npm install deterministic-passkeys
```

## Usage

```ts
import { createPassword, createPasskey } from 'deterministic-passkeys';

const matrix = [
  [2, 2.3, 4],
  [7, 7.8, 7],
  [4.442, 3, 9]
];

const password = createPassword(matrix, { length: 24 });
const passkey = createPasskey(matrix);

console.log(password);
console.log(passkey.publicKeyHex);
```

## Notes

- The matrix is encoded as big-endian float64 values with row length prefixes for deterministic hashing.
- Non-finite values (NaN, Infinity) throw.
- Use `salt` and `info` options to domain-separate different use cases.
