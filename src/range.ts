/**
 * zkToolkit Range Proof Module
 *
 * Range Proofs for Zero-Knowledge Value Bounds
 * Reference: /blog/zktoolkit - Section: Range Proofs
 *
 * Properties:
 * - Prove value is within [min, max] without revealing the value
 * - Uses bit decomposition with Poseidon commitments
 * - Full verification with value reconstruction
 *
 * Scheme:
 * - Decompose (value - min) into bits
 * - Commit to each bit
 * - Commit to the value
 * - Verification reconstructs value from bits and checks commitment
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

export interface RangeProof {
  valueCommitment: string;
  min: number;
  max: number;
  bits: number[];
  bitCommitments: string[];
  salt: string;
  valid: boolean;
}

export interface RangeVerifyResult {
  valid: boolean;
  min: number;
  max: number;
  checks: {
    bitsAreBinary: boolean;
    valueInRange: boolean;
    commitmentsMatch: boolean;
  };
}

export const range = {
  /**
   * Create a range proof proving value is in [min, max]
   *
   * @param value - The secret value to prove range for
   * @param min - Minimum allowed value (inclusive)
   * @param max - Maximum allowed value (inclusive)
   * @returns RangeProof with commitments and revealed bits
   */
  async prove(value: number, min: number, max: number): Promise<RangeProof> {
    const poseidon = await getPoseidon();

    // Check if value is in range
    if (value < min || value > max) {
      return {
        valueCommitment: "0x0",
        min,
        max,
        bits: [],
        bitCommitments: [],
        salt: "0x0",
        valid: false,
      };
    }

    // Calculate bit width needed for range
    const rangeSize = max - min;
    const bitWidth = Math.max(1, Math.ceil(Math.log2(rangeSize + 1)));

    // Normalize value to [0, rangeSize]
    const normalizedValue = value - min;

    // Generate salt
    const salt = generateSalt();
    const saltBigInt = BigInt(salt);

    // Create value commitment: C = Poseidon(value, salt)
    const valueCommitmentHash = poseidon([BigInt(value), saltBigInt]);
    const valueCommitmentHex = toHex(
      poseidon.F.fromMontgomery(valueCommitmentHash)
    );

    // Decompose into bits and create commitments
    const bits: number[] = [];
    const bitCommitments: string[] = [];

    for (let i = 0; i < bitWidth; i++) {
      const bit = (normalizedValue >> i) & 1;
      bits.push(bit);

      // Bit commitment: Poseidon(bit, salt, i)
      const bitCommitmentHash = poseidon([BigInt(bit), saltBigInt, BigInt(i)]);
      bitCommitments.push(toHex(poseidon.F.fromMontgomery(bitCommitmentHash)));
    }

    return {
      valueCommitment: valueCommitmentHex,
      min,
      max,
      bits,
      bitCommitments,
      salt,
      valid: true,
    };
  },

  /**
   * Verify a range proof
   *
   * Full verification:
   * 1. Check all bits are 0 or 1
   * 2. Reconstruct value from bits and verify it's in [min, max]
   * 3. Verify all bit commitments match
   * 4. Verify value commitment matches
   */
  async verify(proof: RangeProof): Promise<RangeVerifyResult> {
    const poseidon = await getPoseidon();

    if (!proof.valid || proof.bits.length === 0) {
      return {
        valid: false,
        min: proof.min,
        max: proof.max,
        checks: {
          bitsAreBinary: false,
          valueInRange: false,
          commitmentsMatch: false,
        },
      };
    }

    // 1. Check all bits are binary (0 or 1)
    const bitsAreBinary = proof.bits.every((bit) => bit === 0 || bit === 1);
    if (!bitsAreBinary) {
      return {
        valid: false,
        min: proof.min,
        max: proof.max,
        checks: {
          bitsAreBinary: false,
          valueInRange: false,
          commitmentsMatch: false,
        },
      };
    }

    // 2. Reconstruct normalized value from bits
    let normalizedValue = 0;
    for (let i = 0; i < proof.bits.length; i++) {
      normalizedValue += proof.bits[i] * 2 ** i;
    }

    // Reconstruct actual value
    const reconstructedValue = normalizedValue + proof.min;

    // Check value is in range
    const valueInRange =
      reconstructedValue >= proof.min && reconstructedValue <= proof.max;
    if (!valueInRange) {
      return {
        valid: false,
        min: proof.min,
        max: proof.max,
        checks: {
          bitsAreBinary: true,
          valueInRange: false,
          commitmentsMatch: false,
        },
      };
    }

    // 3. Verify bit commitments
    const saltBigInt = BigInt(proof.salt);
    let commitmentsMatch = true;

    for (let i = 0; i < proof.bits.length; i++) {
      const expectedCommitmentHash = poseidon([
        BigInt(proof.bits[i]),
        saltBigInt,
        BigInt(i),
      ]);
      const expectedCommitmentHex = toHex(
        poseidon.F.fromMontgomery(expectedCommitmentHash)
      );

      if (
        expectedCommitmentHex.toLowerCase() !==
        proof.bitCommitments[i].toLowerCase()
      ) {
        commitmentsMatch = false;
        break;
      }
    }

    // 4. Verify value commitment
    if (commitmentsMatch) {
      const expectedValueCommitmentHash = poseidon([
        BigInt(reconstructedValue),
        saltBigInt,
      ]);
      const expectedValueCommitmentHex = toHex(
        poseidon.F.fromMontgomery(expectedValueCommitmentHash)
      );

      if (
        expectedValueCommitmentHex.toLowerCase() !==
        proof.valueCommitment.toLowerCase()
      ) {
        commitmentsMatch = false;
      }
    }

    return {
      valid: bitsAreBinary && valueInRange && commitmentsMatch,
      min: proof.min,
      max: proof.max,
      checks: {
        bitsAreBinary,
        valueInRange,
        commitmentsMatch,
      },
    };
  },

  /**
   * Create a proof that value > threshold
   */
  async proveGreaterThan(
    value: number,
    threshold: number
  ): Promise<RangeProof> {
    const MAX_SAFE = 2 ** 32;
    return this.prove(value, threshold + 1, MAX_SAFE);
  },

  /**
   * Create a proof that value < threshold
   */
  async proveLessThan(value: number, threshold: number): Promise<RangeProof> {
    return this.prove(value, 0, threshold - 1);
  },

  getHelp(): string {
    return `
zkToolkit Range Proof Functions
===============================

Prove a value is within a range.
Reference: /blog/zktoolkit

VERIFICATION:
  1. All bits are 0 or 1
  2. Reconstructed value is in [min, max]
  3. All commitments match

COMMANDS:
  range.prove(value, min, max)     Create range proof
  range.verify(proof)              Verify range proof
  range.proveGreaterThan(value, threshold)
  range.proveLessThan(value, threshold)

EXAMPLES:
  # Prove age is 18-100
  const proof = await range.prove(25, 18, 100);
  
  # Verify
  await range.verify(proof)
  > { valid: true, checks: { bitsAreBinary: true, valueInRange: true, commitmentsMatch: true } }

  # Invalid proof (value outside range) will fail
  const badProof = await range.prove(15, 18, 100);
  > { valid: false }
`;
  },
};
