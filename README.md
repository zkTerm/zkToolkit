# @zkterm/toolkit

Zero-Knowledge Cryptography Primitives Toolkit - a collection of ZK-friendly cryptographic functions for building privacy-preserving applications.

## Installation

```bash
npm install @zkterm/toolkit
```

## Usage

### Hash Functions

```typescript
import { hash } from '@zkterm/toolkit';

// Poseidon Hash (~300 constraints in ZK circuits)
const poseidonResult = await hash.poseidon("hello world");
console.log(poseidonResult.hash);
// 0x1a2b3c...

// Hash multiple values
const multiHash = await hash.poseidon(["value1", "value2", "value3"]);

// Pedersen Hash (~1000 constraints, homomorphic)
const pedersenResult = await hash.pedersen("secret message");
console.log(pedersenResult.hash);
console.log(pedersenResult.point); // { x: "...", y: "..." }

// MiMC Hash (~500 constraints)
const mimcResult = await hash.mimc("data", "optional-key");
console.log(mimcResult.hash);
```

## Available Functions

### Hash Category
| Function | Description | Circuit Cost |
|----------|-------------|--------------|
| `hash.poseidon(input)` | ZK-optimized hash, most widely used | ~300 constraints |
| `hash.pedersen(input)` | Homomorphic hash, good for commitments | ~1000 constraints |
| `hash.mimc(input, key?)` | Simple structure, keyed hash | ~500 constraints |

## Planned Features

- **Commit**: Pedersen commitments, reveal & verify
- **Merkle**: Tree construction, inclusion proofs
- **Range**: Range proofs for numeric bounds
- **Sign**: EdDSA signatures for ZK
- **Nullifier**: Double-spend prevention
- **Field**: Field arithmetic operations
- **EC**: Elliptic curve operations
- **Shamir**: Secret sharing schemes
- **Proof**: Groth16, PLONK proof systems

## Why ZK-Friendly Hashes?

Traditional hash functions like SHA-256 require ~25,000 constraints in ZK circuits. ZK-friendly alternatives are designed specifically for efficiency:

- **Poseidon**: Uses algebraic operations native to ZK circuits
- **Pedersen**: Leverages elliptic curve properties
- **MiMC**: Minimal multiplicative complexity

## License

MIT
