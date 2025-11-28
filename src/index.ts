export { hash } from './hash';
export type { PoseidonResult, PedersenResult, MimcResult } from './hash';

export const VERSION = '0.1.0';

export function getInfo() {
  return {
    version: VERSION,
    categories: ['hash', 'commit', 'merkle', 'range', 'sign', 'nullifier', 'field', 'ec', 'shamir', 'proof'],
    description: 'Zero-Knowledge Cryptography Primitives Toolkit',
    implemented: ['hash'],
    planned: ['commit', 'merkle', 'range', 'sign', 'nullifier', 'field', 'ec', 'shamir', 'proof']
  };
}
