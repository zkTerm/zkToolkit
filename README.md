# @zkterm/zktoolkit

Zero-Knowledge Cryptography Primitives Toolkit - a collection of ZK-friendly cryptographic functions for building privacy-preserving applications.

**Documentation**: [/blog/zktoolkit](/blog/zktoolkit)

## Installation

```bash
npm install @zkterm/zktoolkit
```

## Usage

### Hash Functions

```typescript
import { hash } from '@zkterm/zktoolkit';

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

### Commitments

```typescript
import { commit } from '@zkterm/zktoolkit';

// Create a commitment to value 100
const result = await commit.create(100, "my_random_secret");
console.log(result.commitment); // 0x8a7b6c5d...
console.log(result.salt);       // 0x1234567890...

// Later: Reveal and verify
const revealed = await commit.reveal(result.commitment, 100, "my_random_secret");
console.log(revealed.valid);    // true

// Verify with raw salt
const verified = await commit.verify(result.commitment, 100, result.salt);
console.log(verified.valid);    // true
```

## Available Functions

### Hash Category
| Function | Description | Circuit Cost |
|----------|-------------|--------------|
| `hash.poseidon(input)` | ZK-optimized hash, most widely used | ~300 constraints |
| `hash.pedersen(input)` | Homomorphic hash, good for commitments | ~1000 constraints |
| `hash.mimc(input, key?)` | Simple structure, keyed hash | ~500 constraints |

### Commit Category
| Function | Description | Use Case |
|----------|-------------|----------|
| `commit.create(value, secret?)` | Create commitment to value | Hide value, reveal later |
| `commit.reveal(commitment, value, secret)` | Reveal and verify | Prove original value |
| `commit.verify(commitment, value, salt)` | Verify with raw salt | External verification |

**Properties:**
- **Hiding**: Commitment reveals nothing about the value
- **Binding**: Cannot open commitment to a different value

**Use Cases:**
- Sealed-bid auctions (commit bid, reveal after deadline)
- Voting systems (commit vote, reveal when polls close)
- Random number generation (commit-reveal scheme)
- Privacy tokens (hide amounts in ZK proofs)

## Planned Features

- **Merkle**: Tree construction, inclusion proofs
- **Range**: Range proofs for numeric bounds
- **Sign**: EdDSA signatures for ZK
- **Nullifier**: Double-spend prevention
- **Field**: Field arithmetic operations
- **EC**: Elliptic curve operations
- **Shamir**: Secret sharing schemes
- **Proof**: Groth16, PLONK proof systems

## Why ZK-Friendly Primitives?

Traditional hash functions like SHA-256 require ~25,000 constraints in ZK circuits. ZK-friendly alternatives are designed specifically for efficiency:

- **Poseidon**: Uses algebraic operations native to ZK circuits
- **Pedersen**: Leverages elliptic curve properties
- **MiMC**: Minimal multiplicative complexity

## License

MIT
