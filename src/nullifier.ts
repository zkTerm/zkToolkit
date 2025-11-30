/**
 * zkToolkit Nullifier Module
 *
 * Nullifiers for Zero-Knowledge Double-Spend Prevention
 * Reference: /blog/zktoolkit - Section: Nullifiers
 *
 * Properties:
 * - Deterministic: Same (secret, scope) always produces same nullifier
 * - Unlinkable: Cannot determine secret from nullifier
 * - Unique per scope: Same secret produces different nullifiers for different scopes
 *
 * Formula: nullifier = Poseidon(secret, scope)
 * Uses Poseidon hash for ZK-circuit efficiency
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

function stringToFieldElement(input: string): bigint {
  if (input.startsWith("0x")) {
    return BigInt(input);
  }
  const encoder = new TextEncoder();
  const bytes = encoder.encode(input);
  let result = BigInt(0);
  for (let i = 0; i < bytes.length && i < 31; i++) {
    result = result * BigInt(256) + BigInt(bytes[i]);
  }
  return result;
}

export interface NullifierResult {
  nullifier: string;
  scope: string;
  algorithm: "Poseidon";
}

export interface NullifierVerifyResult {
  valid: boolean;
  nullifier: string;
  expectedNullifier: string;
  scope: string;
}

export interface NullifierSet {
  nullifiers: Set<string>;
  scope: string;
  size: number;
}

export const nullifier = {
  /**
   * Create a nullifier from a secret and scope
   *
   * @param secret - The private secret (e.g., spending key, vote secret)
   * @param scope - The scope/context for this nullifier (e.g., "vote:election2024")
   * @returns NullifierResult with the deterministic nullifier hash
   *
   * @example
   * const n = await nullifier.create("my_spending_key", "tx:001");
   * // { nullifier: "0x...", scope: "tx:001" }
   */
  async create(secret: string, scope: string): Promise<NullifierResult> {
    const poseidon = await getPoseidon();

    const secretField = stringToFieldElement(secret);
    const scopeField = stringToFieldElement(scope);

    // nullifier = Poseidon(secret, scope)
    const hash = poseidon([secretField, scopeField]);
    const nullifierHex = toHex(poseidon.F.fromMontgomery(hash));

    return {
      nullifier: nullifierHex,
      scope,
      algorithm: "Poseidon",
    };
  },

  /**
   * Verify that a nullifier matches a secret and scope
   *
   * @param nullifierHash - The nullifier to verify
   * @param secret - The secret to check against
   * @param scope - The scope used in the nullifier
   * @returns NullifierVerifyResult indicating if nullifier is valid
   *
   * @example
   * const result = await nullifier.verify("0x...", "my_secret", "scope:001");
   * // { valid: true, nullifier: "0x...", expectedNullifier: "0x..." }
   */
  async verify(
    nullifierHash: string,
    secret: string,
    scope: string
  ): Promise<NullifierVerifyResult> {
    const poseidon = await getPoseidon();

    const secretField = stringToFieldElement(secret);
    const scopeField = stringToFieldElement(scope);

    // Recompute expected nullifier
    const hash = poseidon([secretField, scopeField]);
    const expectedNullifier = toHex(poseidon.F.fromMontgomery(hash));

    const valid =
      expectedNullifier.toLowerCase() === nullifierHash.toLowerCase();

    return {
      valid,
      nullifier: nullifierHash,
      expectedNullifier,
      scope,
    };
  },

  /**
   * Create a nullifier set for tracking used nullifiers
   *
   * @param scope - The scope for this nullifier set
   * @returns NullifierSet object for tracking used nullifiers
   *
   * @example
   * const set = nullifier.createSet("election:2024");
   * // Use set.add(n) to add nullifiers, set.has(n) to check
   */
  createSet(scope: string): NullifierSet {
    return {
      nullifiers: new Set<string>(),
      scope,
      size: 0,
    };
  },

  /**
   * Add a nullifier to a set (marks as used)
   *
   * @param set - The nullifier set
   * @param nullifierHash - The nullifier to add
   * @returns true if added (was new), false if already existed (double-spend!)
   */
  addToSet(set: NullifierSet, nullifierHash: string): boolean {
    const normalizedHash = nullifierHash.toLowerCase();
    if (set.nullifiers.has(normalizedHash)) {
      return false; // Double spend detected!
    }
    set.nullifiers.add(normalizedHash);
    set.size = set.nullifiers.size;
    return true;
  },

  /**
   * Check if a nullifier exists in a set
   *
   * @param set - The nullifier set
   * @param nullifierHash - The nullifier to check
   * @returns true if nullifier already used
   */
  isInSet(set: NullifierSet, nullifierHash: string): boolean {
    return set.nullifiers.has(nullifierHash.toLowerCase());
  },

  /**
   * Generate a random secret for nullifier creation
   *
   * @returns Random 32-byte hex string
   */
  generateSecret(): string {
    return "0x" + crypto.randomBytes(32).toString("hex");
  },

  /**
   * Create multiple nullifiers for batch operations
   *
   * @param secret - The shared secret
   * @param scopes - Array of scopes
   * @returns Array of NullifierResults
   */
  async createBatch(
    secret: string,
    scopes: string[]
  ): Promise<NullifierResult[]> {
    return Promise.all(scopes.map((scope) => this.create(secret, scope)));
  },

  /**
   * Get help text for nullifier functions
   */
  getHelp(): string {
    return `
zkToolkit Nullifier Functions
=============================

Nullifiers for preventing double-spending in ZK systems.
Reference: /blog/zktoolkit

PROPERTIES:
  - Deterministic: Same inputs = same nullifier
  - Unlinkable: Can't derive secret from nullifier
  - Scoped: Different scopes = different nullifiers

COMMANDS:
  nullifier.create(secret, scope)   Create nullifier hash
  nullifier.verify(hash, secret, scope)  Verify nullifier
  nullifier.createSet(scope)        Create tracking set
  nullifier.addToSet(set, hash)     Add (returns false if double-spend)
  nullifier.isInSet(set, hash)      Check if already used
  nullifier.generateSecret()        Generate random secret

EXAMPLES:
  # Create a nullifier for a vote
  const n = await nullifier.create("my_voter_secret", "election:2024");
  > { nullifier: "0x7a8b9c...", scope: "election:2024" }

  # Track used nullifiers to prevent double-voting
  const usedVotes = nullifier.createSet("election:2024");
  
  # Try to use nullifier (first time succeeds)
  nullifier.addToSet(usedVotes, n.nullifier)
  > true

  # Try again (detected as double-spend!)
  nullifier.addToSet(usedVotes, n.nullifier)
  > false

USE CASES:
  - Voting (prevent double-voting)
  - Token transfers (prevent double-spend)
  - Airdrop claims (one claim per address)
  - Ticket systems (prevent reuse)
`;
  },
};
