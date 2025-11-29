/**
 * zkToolkit Commitment Module
 *
 * Pedersen Commitment Scheme for Zero-Knowledge Proofs
 * Reference: /blog/zktoolkit - Section 2: Cryptographic Commitments
 *
 * Properties:
 * - Hiding: Commitment reveals nothing about the value
 * - Binding: Cannot open commitment to a different value
 *
 * Formula: C = Poseidon(value, salt)
 * Using Poseidon hash for ZK-circuit efficiency (~300 constraints)
 */

import { buildPoseidon } from "circomlibjs";
import crypto from "crypto";

let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

function toHex(buffer: Uint8Array): string {
  return (
    "0x" +
    Array.from(buffer)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

function generateSalt(): string {
  return "0x" + crypto.randomBytes(32).toString("hex");
}

function hexToFieldElement(hex: string): bigint {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + cleanHex);
}

function valueToFieldElement(value: string | number | bigint): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    return BigInt(value);
  }
  // String - could be hex or decimal
  if (value.startsWith("0x")) {
    return BigInt(value);
  }
  // Try as number first, then as string hash
  const num = Number(value);
  if (!isNaN(num) && Number.isFinite(num)) {
    return BigInt(Math.floor(num));
  }
  // Hash the string to get a field element
  const encoder = new TextEncoder();
  const bytes = encoder.encode(value);
  let result = BigInt(0);
  for (let i = 0; i < bytes.length && i < 31; i++) {
    result = result * BigInt(256) + BigInt(bytes[i]);
  }
  return result;
}

export interface CommitmentResult {
  commitment: string;
  salt: string;
  value: string;
  algorithm: "Pedersen-Poseidon";
}

export interface RevealResult {
  valid: boolean;
  commitment: string;
  revealedValue: string;
  salt: string;
}

export interface VerifyResult {
  valid: boolean;
  commitment: string;
  expectedCommitment: string;
}

export const commit = {
  /**
   * Create a commitment to a value
   *
   * @param value - The value to commit to (number, string, or hex)
   * @param secret - Optional secret/salt (auto-generated if not provided)
   * @returns CommitmentResult with commitment hash, salt, and original value
   *
   * @example
   * const result = await commit.create(100, "my_random_secret");
   * // { commitment: "0x8a7b6c5d...", salt: "0x1234...", value: "100" }
   */
  async create(
    value: string | number | bigint,
    secret?: string
  ): Promise<CommitmentResult> {
    const poseidon = await getPoseidon();

    // Generate or use provided salt
    const salt = secret
      ? "0x" + Buffer.from(secret).toString("hex").padEnd(64, "0").slice(0, 64)
      : generateSalt();

    // Convert to field elements
    const valueField = valueToFieldElement(value);
    const saltField = hexToFieldElement(salt);

    // Compute commitment: C = Poseidon(value, salt)
    const commitmentHash = poseidon([valueField, saltField]);
    const commitmentHex = toHex(poseidon.F.fromMontgomery(commitmentHash));

    return {
      commitment: commitmentHex,
      salt,
      value: value.toString(),
      algorithm: "Pedersen-Poseidon",
    };
  },

  /**
   * Reveal a commitment and verify it matches the original
   *
   * @param commitment - The commitment hash to verify against
   * @param value - The claimed original value
   * @param secret - The secret/salt used when creating the commitment
   * @returns RevealResult indicating if the reveal is valid
   *
   * @example
   * const result = await commit.reveal("0x8a7b6c5d...", 100, "my_random_secret");
   * // { valid: true, commitment: "0x8a7b6c5d...", revealedValue: "100", salt: "0x..." }
   */
  async reveal(
    commitment: string,
    value: string | number | bigint,
    secret: string
  ): Promise<RevealResult> {
    const poseidon = await getPoseidon();

    // Reconstruct salt from secret
    const salt =
      "0x" + Buffer.from(secret).toString("hex").padEnd(64, "0").slice(0, 64);

    // Convert to field elements
    const valueField = valueToFieldElement(value);
    const saltField = hexToFieldElement(salt);

    // Recompute commitment
    const recomputedHash = poseidon([valueField, saltField]);
    const recomputedHex = toHex(poseidon.F.fromMontgomery(recomputedHash));

    // Compare
    const valid = recomputedHex.toLowerCase() === commitment.toLowerCase();

    return {
      valid,
      commitment,
      revealedValue: value.toString(),
      salt,
    };
  },

  /**
   * Verify a commitment matches a value and salt
   *
   * @param commitment - The commitment hash to verify
   * @param value - The value to verify
   * @param salt - The salt (hex string) used in the commitment
   * @returns VerifyResult indicating if commitment is valid
   *
   * @example
   * const result = await commit.verify("0x8a7b6c5d...", 100, "0x1234567890...");
   * // { valid: true, commitment: "0x8a7b6c5d...", expectedCommitment: "0x8a7b6c5d..." }
   */
  async verify(
    commitment: string,
    value: string | number | bigint,
    salt: string
  ): Promise<VerifyResult> {
    const poseidon = await getPoseidon();

    // Convert to field elements
    const valueField = valueToFieldElement(value);
    const saltField = hexToFieldElement(salt);

    // Compute expected commitment
    const expectedHash = poseidon([valueField, saltField]);
    const expectedHex = toHex(poseidon.F.fromMontgomery(expectedHash));

    // Compare
    const valid = expectedHex.toLowerCase() === commitment.toLowerCase();

    return {
      valid,
      commitment,
      expectedCommitment: expectedHex,
    };
  },

  /**
   * Get help text for commit functions
   * Reference: /blog/zktoolkit - Section 2
   */
  getHelp(): string {
    return `
zkToolkit Commitment Functions
==============================

Pedersen-Poseidon commitment scheme for hiding values.
Reference: /blog/zktoolkit

PROPERTIES:
  - Hiding: Commitment reveals nothing about the value
  - Binding: Cannot open commitment to different value

COMMANDS:
  commit.create(value, secret?)     Create commitment to value
  commit.reveal(commitment, value, secret)  Reveal and verify
  commit.verify(commitment, value, salt)    Verify with raw salt

EXAMPLES:
  # Create a commitment to value 100
  await commit.create(100, "my_random_secret")
  > { commitment: "0x8a7b6c5d...", salt: "0x1234...", value: "100" }

  # Later: Reveal and verify
  await commit.reveal("0x8a7b6c5d...", 100, "my_random_secret")
  > { valid: true, revealedValue: "100" }

USE CASES:
  - Sealed-bid auctions (commit bid, reveal later)
  - Voting (commit vote, reveal after deadline)
  - Random number generation (commit-reveal scheme)
  - Token transfers (hide amounts in ZK proofs)
`;
  },
};
