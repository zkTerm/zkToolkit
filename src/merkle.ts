/**
 * zkToolkit Merkle Tree Module
 *
 * Merkle Trees for Zero-Knowledge Membership Proofs
 * Reference: /blog/zktoolkit - Section 3: Merkle Trees
 *
 * Properties:
 * - Efficient membership proofs: O(log n) proof size
 * - ZK-friendly using Poseidon hash
 * - Supports arbitrary tree depth
 *
 * Uses Poseidon hash for ZK-circuit efficiency (~300 constraints per level)
 */

import { buildPoseidon } from "circomlibjs";

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

export interface MerkleTree {
  root: string;
  leaves: string[];
  levels: string[][];
  depth: number;
}

export interface MerkleProof {
  leaf: string;
  index: number;
  pathElements: string[];
  pathIndices: number[];
  root: string;
}

export interface MerkleVerifyResult {
  valid: boolean;
  computedRoot: string;
  expectedRoot: string;
  leaf: string;
}

export const merkle = {
  /**
   * Create a Merkle tree from an array of leaves
   *
   * @param leaves - Array of values to include in the tree
   * @returns MerkleTree object with root, leaves, and all levels
   *
   * @example
   * const tree = await merkle.create(["alice", "bob", "charlie", "dave"]);
   * // { root: "0x...", leaves: [...], depth: 2 }
   */
  async create(leaves: string[]): Promise<MerkleTree> {
    const poseidon = await getPoseidon();

    if (leaves.length === 0) {
      throw new Error("Cannot create Merkle tree with no leaves");
    }

    // Pad to power of 2
    let paddedLeaves = [...leaves];
    while (paddedLeaves.length & (paddedLeaves.length - 1)) {
      paddedLeaves.push("0");
    }
    if (paddedLeaves.length === 1) {
      paddedLeaves.push("0");
    }

    // Hash all leaves
    const levels: string[][] = [];
    let currentLevel = await Promise.all(
      paddedLeaves.map(async (leaf) => {
        const field = stringToFieldElement(leaf);
        const hash = poseidon([field]);
        return toHex(poseidon.F.fromMontgomery(hash));
      })
    );
    levels.push(currentLevel);

    // Build tree bottom-up
    while (currentLevel.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = BigInt(currentLevel[i]);
        const right = BigInt(currentLevel[i + 1]);
        const hash = poseidon([left, right]);
        nextLevel.push(toHex(poseidon.F.fromMontgomery(hash)));
      }
      levels.push(nextLevel);
      currentLevel = nextLevel;
    }

    const depth = Math.log2(paddedLeaves.length);

    return {
      root: currentLevel[0],
      leaves: paddedLeaves,
      levels,
      depth,
    };
  },

  /**
   * Generate a Merkle proof for a leaf at a given index
   *
   * @param tree - The Merkle tree
   * @param index - Index of the leaf to prove
   * @returns MerkleProof with path elements and indices
   *
   * @example
   * const proof = await merkle.proof(tree, 2);
   * // { pathElements: [...], pathIndices: [...], root: "0x..." }
   */
  async proof(tree: MerkleTree, index: number): Promise<MerkleProof> {
    if (index < 0 || index >= tree.leaves.length) {
      throw new Error(
        `Index ${index} out of bounds (0-${tree.leaves.length - 1})`
      );
    }

    const pathElements: string[] = [];
    const pathIndices: number[] = [];
    let currentIndex = index;

    for (let level = 0; level < tree.levels.length - 1; level++) {
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      pathElements.push(tree.levels[level][siblingIndex]);
      pathIndices.push(isRightNode ? 1 : 0);

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leaf: tree.leaves[index],
      index,
      pathElements,
      pathIndices,
      root: tree.root,
    };
  },

  /**
   * Verify a Merkle proof against a root
   *
   * @param root - The Merkle root to verify against
   * @param leaf - The leaf value being proven
   * @param proof - The proof path elements and indices
   * @returns MerkleVerifyResult indicating if proof is valid
   *
   * @example
   * const result = await merkle.verify(tree.root, "charlie", proof);
   * // { valid: true, computedRoot: "0x...", expectedRoot: "0x..." }
   */
  async verify(
    root: string,
    leaf: string,
    proof: { pathElements: string[]; pathIndices: number[] }
  ): Promise<MerkleVerifyResult> {
    const poseidon = await getPoseidon();

    // Hash the leaf
    const leafField = stringToFieldElement(leaf);
    let currentHash = poseidon([leafField]);
    let currentHex = toHex(poseidon.F.fromMontgomery(currentHash));

    // Traverse up the tree
    for (let i = 0; i < proof.pathElements.length; i++) {
      const sibling = BigInt(proof.pathElements[i]);
      const current = BigInt(currentHex);

      // pathIndex 0 = current is left, pathIndex 1 = current is right
      const left = proof.pathIndices[i] === 0 ? current : sibling;
      const right = proof.pathIndices[i] === 0 ? sibling : current;

      currentHash = poseidon([left, right]);
      currentHex = toHex(poseidon.F.fromMontgomery(currentHash));
    }

    const valid = currentHex.toLowerCase() === root.toLowerCase();

    return {
      valid,
      computedRoot: currentHex,
      expectedRoot: root,
      leaf,
    };
  },

  /**
   * Get help text for merkle functions
   */
  getHelp(): string {
    return `
zkToolkit Merkle Tree Functions
===============================

Merkle trees for efficient ZK membership proofs.
Reference: /blog/zktoolkit

PROPERTIES:
  - O(log n) proof size for n elements
  - ZK-friendly Poseidon hash (~300 constraints/level)
  - Perfect for whitelists, airdrops, voting

COMMANDS:
  merkle.create(leaves)           Build tree from data array
  merkle.proof(tree, index)       Generate membership proof
  merkle.verify(root, leaf, proof)  Verify proof against root

EXAMPLES:
  # Create a tree
  const tree = await merkle.create(["alice", "bob", "charlie", "dave"]);
  > { root: "0x...", depth: 2, leaves: [...] }

  # Generate proof for "charlie" (index 2)
  const proof = await merkle.proof(tree, 2);
  > { pathElements: [...], pathIndices: [...] }

  # Verify the proof
  await merkle.verify(tree.root, "charlie", proof)
  > { valid: true }

USE CASES:
  - Airdrop eligibility (prove address in Merkle root)
  - Private voting (prove voter is registered)
  - KYC verification (prove identity without revealing)
`;
  },
};
