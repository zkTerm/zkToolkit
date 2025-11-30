/**
 * zkToolkit Signature Module
 *
 * EdDSA Digital Signatures over Baby Jubjub Curve
 * Reference: /blog/zktoolkit - Section: Digital Signatures
 *
 * Properties:
 * - EdDSA over Baby Jubjub curve (ZK-friendly)
 * - Uses Poseidon hash for efficiency in ZK circuits
 * - Proper cryptographic verification (forgery-resistant)
 *
 * REQUIREMENTS:
 * - circomlibjs must export buildEddsa and buildBabyjub
 * - Will throw error if EdDSA is not available
 */

import { buildPoseidon } from "circomlibjs";
import crypto from "crypto";

// Type definitions for circomlibjs EdDSA (not in @types)
interface EdDSA {
  prv2pub(privateKey: Buffer): [any, any];
  signPoseidon(privateKey: Buffer, msg: bigint): { R8: [any, any]; S: bigint };
  verifyPoseidon(
    msg: bigint,
    sig: { R8: [any, any]; S: bigint },
    pubKey: [any, any]
  ): boolean;
}

interface BabyJub {
  F: any;
  packPoint(point: [any, any]): Uint8Array;
  unpackPoint(packed: Buffer): [any, any] | null;
}

let poseidonInstance: any = null;
let eddsaInstance: EdDSA | null = null;
let babyjubInstance: BabyJub | null = null;
let eddsaCheckDone = false;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

async function initEddsaAndBabyjub(): Promise<{
  eddsa: EdDSA;
  babyjub: BabyJub;
}> {
  if (!eddsaCheckDone) {
    try {
      const circomlibjs = require("circomlibjs") as any;
      if (
        typeof circomlibjs.buildEddsa === "function" &&
        typeof circomlibjs.buildBabyjub === "function"
      ) {
        eddsaInstance = await circomlibjs.buildEddsa();
        babyjubInstance = await circomlibjs.buildBabyjub();
      }
    } catch {
      // EdDSA not available
    }
    eddsaCheckDone = true;
  }

  if (!eddsaInstance || !babyjubInstance) {
    throw new Error(
      "EdDSA not available. This module requires circomlibjs with EdDSA support. " +
        "Ensure circomlibjs is properly installed and exports buildEddsa and buildBabyjub."
    );
  }

  return { eddsa: eddsaInstance, babyjub: babyjubInstance };
}

function bufferToHex(buffer: Uint8Array | Buffer): string {
  return (
    "0x" +
    Array.from(buffer)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

function hexToBuffer(hex: string): Buffer {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Buffer.from(cleanHex, "hex");
}

function fieldToHex(poseidon: any, fieldElement: any): string {
  const decStr = poseidon.F.toString(fieldElement);
  const bigint = BigInt(decStr);
  return "0x" + bigint.toString(16).padStart(64, "0");
}

// Hash full message using Poseidon in chunks to handle long messages
async function hashMessage(poseidon: any, message: string): Promise<bigint> {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(message);

  // Split message into 31-byte chunks and hash each
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, i + 31);
    let chunkValue = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      chunkValue = chunkValue * BigInt(256) + BigInt(chunk[j]);
    }
    chunks.push(chunkValue);
  }

  // If no chunks, hash empty
  if (chunks.length === 0) {
    chunks.push(BigInt(0));
  }

  // Hash all chunks together (Poseidon supports up to ~16 inputs)
  // For very long messages, hash in batches
  let currentHash = poseidon(chunks.slice(0, Math.min(chunks.length, 16)));
  for (let i = 16; i < chunks.length; i += 15) {
    const batch = chunks.slice(i, Math.min(i + 15, chunks.length));
    currentHash = poseidon([currentHash, ...batch]);
  }

  const hashHex = fieldToHex(poseidon, currentHash);
  return BigInt(hashHex);
}

export interface Keypair {
  privateKey: string;
  publicKey: string;
  publicKeyXY: { x: string; y: string };
}

export interface Signature {
  R8: string; // Packed point as hex
  S: string;
  message: string;
  messageHash: string;
  publicKey: string;
}

export interface SignVerifyResult {
  valid: boolean;
  message: string;
  publicKey: string;
}

export const sign = {
  /**
   * Check if EdDSA is available
   */
  async isEddsaAvailable(): Promise<boolean> {
    try {
      await initEddsaAndBabyjub();
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Generate a new EdDSA keypair
   *
   * @throws Error if EdDSA is not available
   */
  async generateKeypair(): Promise<Keypair> {
    const { eddsa, babyjub } = await initEddsaAndBabyjub();

    const privateKeyBytes = crypto.randomBytes(32);
    const privateKeyHex = bufferToHex(privateKeyBytes);

    const publicKey = eddsa.prv2pub(privateKeyBytes as Buffer);
    const packedPubKey = babyjub.packPoint(publicKey);

    return {
      privateKey: privateKeyHex,
      publicKey: bufferToHex(packedPubKey),
      publicKeyXY: {
        x: babyjub.F.toString(publicKey[0]),
        y: babyjub.F.toString(publicKey[1]),
      },
    };
  },

  /**
   * Sign a message with a private key (EdDSA)
   *
   * @throws Error if EdDSA is not available
   */
  async sign(message: string, privateKey: string): Promise<Signature> {
    const { eddsa, babyjub } = await initEddsaAndBabyjub();
    const poseidon = await getPoseidon();

    const privKeyHex = privateKey.startsWith("0x")
      ? privateKey.slice(2)
      : privateKey;
    const privKeyBytes = Buffer.from(privKeyHex, "hex");

    // Hash full message
    const msgBigInt = await hashMessage(poseidon, message);
    const messageHashHex = "0x" + msgBigInt.toString(16).padStart(64, "0");

    // Get public key
    const publicKey = eddsa.prv2pub(privKeyBytes);
    const packedPubKey = babyjub.packPoint(publicKey);

    // Create EdDSA signature
    const signature = eddsa.signPoseidon(privKeyBytes, msgBigInt);

    // Pack R8 point for storage (consistent serialization)
    const packedR8 = babyjub.packPoint(signature.R8);

    return {
      R8: bufferToHex(packedR8),
      S: signature.S.toString(),
      message,
      messageHash: messageHashHex,
      publicKey: bufferToHex(packedPubKey),
    };
  },

  /**
   * Verify a signature (EdDSA verification)
   *
   * @throws Error if EdDSA is not available
   */
  async verify(
    message: string,
    signature: Signature,
    publicKey: string
  ): Promise<SignVerifyResult> {
    const { eddsa, babyjub } = await initEddsaAndBabyjub();
    const poseidon = await getPoseidon();

    try {
      // Verify message hash
      const expectedMsgBigInt = await hashMessage(poseidon, message);
      const expectedHashHex =
        "0x" + expectedMsgBigInt.toString(16).padStart(64, "0");

      if (
        expectedHashHex.toLowerCase() !== signature.messageHash.toLowerCase()
      ) {
        return { valid: false, message, publicKey };
      }

      // Unpack public key
      const packedPubKeyBytes = hexToBuffer(publicKey);
      const pubKeyPoint = babyjub.unpackPoint(packedPubKeyBytes);

      if (!pubKeyPoint) {
        return { valid: false, message, publicKey };
      }

      // Unpack R8 point
      const packedR8Bytes = hexToBuffer(signature.R8);
      const R8Point = babyjub.unpackPoint(packedR8Bytes);

      if (!R8Point) {
        return { valid: false, message, publicKey };
      }

      // Reconstruct signature with unpacked R8
      const sig = {
        R8: R8Point as [any, any],
        S: BigInt(signature.S),
      };

      // Verify using EdDSA
      const msgBigInt = BigInt(signature.messageHash);
      const valid = eddsa.verifyPoseidon(msgBigInt, sig, pubKeyPoint);

      return { valid, message, publicKey };
    } catch {
      return { valid: false, message, publicKey };
    }
  },

  /**
   * Derive public key from private key
   *
   * @throws Error if EdDSA is not available
   */
  async derivePublicKey(privateKey: string): Promise<string> {
    const { eddsa, babyjub } = await initEddsaAndBabyjub();

    const privKeyHex = privateKey.startsWith("0x")
      ? privateKey.slice(2)
      : privateKey;
    const privKeyBytes = Buffer.from(privKeyHex, "hex");

    const publicKey = eddsa.prv2pub(privKeyBytes);
    const packedPubKey = babyjub.packPoint(publicKey);
    return bufferToHex(packedPubKey);
  },

  getHelp(): string {
    return `
zkToolkit Signature Functions
=============================

EdDSA signatures over Baby Jubjub curve.
Reference: /blog/zktoolkit

REQUIREMENTS:
  circomlibjs must be installed with EdDSA support.
  Functions will throw if EdDSA is unavailable.

PROPERTIES:
  - ZK-friendly curve (~5000 constraints)
  - Poseidon-based message hashing
  - Proper cryptographic verification (forgery-resistant)
  - Supports messages of any length

COMMANDS:
  sign.isEddsaAvailable()          Check EdDSA availability
  sign.generateKeypair()           Generate EdDSA keypair
  sign.sign(message, privateKey)   Sign a message
  sign.verify(message, sig, pubKey)  Verify signature
  sign.derivePublicKey(privateKey)   Derive public key

EXAMPLES:
  // Check availability first
  if (await sign.isEddsaAvailable()) {
    const keypair = await sign.generateKeypair();
    const sig = await sign.sign("hello", keypair.privateKey);
    await sign.verify("hello", sig, keypair.publicKey)
    > { valid: true }
  }
`;
  },
};
