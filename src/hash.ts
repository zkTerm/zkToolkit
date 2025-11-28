import { buildPoseidon, buildMimcSponge, buildPedersenHash } from 'circomlibjs';

let poseidonInstance: any = null;
let mimcInstance: any = null;
let pedersenInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

async function getMimc() {
  if (!mimcInstance) {
    mimcInstance = await buildMimcSponge();
  }
  return mimcInstance;
}

async function getPedersen() {
  if (!pedersenInstance) {
    pedersenInstance = await buildPedersenHash();
  }
  return pedersenInstance;
}

function toHex(buffer: Uint8Array): string {
  return '0x' + Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

function stringToFieldElement(input: string): bigint {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(input);
  let result = BigInt(0);
  for (let i = 0; i < bytes.length && i < 31; i++) {
    result = result * BigInt(256) + BigInt(bytes[i]);
  }
  return result;
}

export interface PoseidonResult {
  hash: string;
  algorithm: 'Poseidon';
  input: string | string[];
}

export interface PedersenResult {
  hash: string;
  point: { x: string; y: string };
  algorithm: 'Pedersen';
  input: string;
}

export interface MimcResult {
  hash: string;
  algorithm: 'MiMC';
  input: string;
  key: string;
}

export const hash = {
  async poseidon(input: string | string[]): Promise<PoseidonResult> {
    const poseidon = await getPoseidon();
    
    let inputs: bigint[];
    if (Array.isArray(input)) {
      inputs = input.map(i => stringToFieldElement(i));
    } else {
      inputs = [stringToFieldElement(input)];
    }
    
    const hashResult = poseidon(inputs);
    const hashHex = toHex(poseidon.F.fromMontgomery(hashResult));
    
    return {
      hash: hashHex,
      algorithm: 'Poseidon',
      input
    };
  },

  async pedersen(input: string): Promise<PedersenResult> {
    const pedersen = await getPedersen();
    
    const encoder = new TextEncoder();
    const bytes = encoder.encode(input);
    const buffer = Buffer.from(bytes);
    
    const hashResult = pedersen.hash(buffer);
    const unpackedPoint = pedersen.babyJub.unpackPoint(hashResult);
    
    return {
      hash: toHex(hashResult),
      point: {
        x: unpackedPoint[0].toString(),
        y: unpackedPoint[1].toString()
      },
      algorithm: 'Pedersen',
      input
    };
  },

  async mimc(input: string, key?: string): Promise<MimcResult> {
    const mimc = await getMimc();
    
    const inputField = stringToFieldElement(input);
    const keyField = key ? stringToFieldElement(key) : BigInt(0);
    
    const hashResult = mimc.multiHash([inputField], keyField);
    const hashHex = '0x' + mimc.F.toString(hashResult, 16).padStart(64, '0');
    
    return {
      hash: hashHex,
      algorithm: 'MiMC',
      input,
      key: key || '0'
    };
  },

  getHelp(): string {
    return `
zkToolkit Hash Functions
========================

ZK-friendly hash functions optimized for circuit constraints.

COMMANDS:
  hash.poseidon(input)     Hash using Poseidon (~300 constraints)
  hash.pedersen(input)     Hash using Pedersen (~1000 constraints)
  hash.mimc(input, key?)   Hash using MiMC (~500 constraints)

EXAMPLES:
  await hash.poseidon("hello world")
  await hash.poseidon(["val1", "val2", "val3"])
  await hash.pedersen("secret message")
  await hash.mimc("data", "mykey")

COMPARISON:
  - Poseidon: Fastest in ZK circuits, most widely used
  - Pedersen: Homomorphic properties, good for commitments
  - MiMC: Simple structure, higher round count
  - SHA-256: ~25,000 constraints (avoid in ZK!)
`;
  }
};
