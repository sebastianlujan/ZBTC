// BIP341 key-path Taproot, written out by hand so every step of the demo's
// spend can be checked line by line against the BIP.
//
// Data flow: secret key d → internal key P = x(d·G) → tweak
// t = H_TapTweak(P ‖ merkleRoot) → output key Q = lift_x(P) + t·G →
// scriptPubKey OP_1 PUSH32 x(Q). The demo commits to no script tree, so its
// merkleRoot is empty; the BIP341 vectors exercise the general form.
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { SECRET_KEY_BYTES, X_ONLY_KEY_BYTES } from './constants.js';

const { Point } = schnorr;
const { lift_x, pointToBytes, randomSecretKey, taggedHash } = schnorr.utils;
const CURVE_ORDER = Point.Fn.ORDER;

const TAP_TWEAK_TAG = 'TapTweak';
/** No script tree: the tweak commits to the internal key alone. */
const NO_SCRIPT_TREE = new Uint8Array(0);
/** Segwit version 1 is pushed as OP_1. */
const OP_1 = 0x51;

type PointType = ReturnType<typeof lift_x>;

// ---- Keys ----

/** Always exactly 32 bytes, unlike encodings that drop leading zero bytes. */
export function generateSecretKey(): Uint8Array {
  return randomSecretKey();
}

/** P: the x-only key BIP340 derives from d. */
export function internalKey(secretKey: Uint8Array): Uint8Array {
  return schnorr.getPublicKey(secretKey);
}

function hasEvenY(point: PointType): boolean {
  return point.toAffine().y % 2n === 0n;
}

// ---- Tweak ----

/** t = H_TapTweak(P ‖ merkleRoot) as an integer. BIP341 treats t ≥ n as a failure. */
export function tapTweak(xOnlyKey: Uint8Array, merkleRoot = NO_SCRIPT_TREE): bigint {
  const tweak = bytesToNumberBE(taggedHash(TAP_TWEAK_TAG, xOnlyKey, merkleRoot));
  if (tweak >= CURVE_ORDER) throw new RangeError('TapTweak is not below the curve order');
  return tweak;
}

/** Q = lift_x(P) + t·G, x-only. */
export function tweakPublicKey(xOnlyKey: Uint8Array, merkleRoot = NO_SCRIPT_TREE): Uint8Array {
  const tweakPoint = Point.BASE.multiply(tapTweak(xOnlyKey, merkleRoot));
  return pointToBytes(lift_x(bytesToNumberBE(xOnlyKey)).add(tweakPoint));
}

/**
 * d' = ±d + t (mod n), the key that signs for Q. P is lift_x(x(d·G)), the
 * even-Y point, so d is negated first when d·G has odd Y.
 */
export function tweakSecretKey(secretKey: Uint8Array, merkleRoot = NO_SCRIPT_TREE): Uint8Array {
  if (secretKey.length !== SECRET_KEY_BYTES) throw new RangeError(`secret key must be ${SECRET_KEY_BYTES} bytes`);
  const secret = bytesToNumberBE(secretKey);
  const publicPoint = Point.BASE.multiply(secret);
  const evenSecret = hasEvenY(publicPoint) ? secret : CURVE_ORDER - secret;
  const tweaked = (evenSecret + tapTweak(pointToBytes(publicPoint), merkleRoot)) % CURVE_ORDER;
  if (tweaked === 0n) throw new RangeError('tweaked secret key is zero');
  return numberToBytesBE(tweaked, SECRET_KEY_BYTES);
}

// ---- Output ----

/** OP_1 PUSH32 x(Q): the segwit v1 output that pays the tweaked key. */
export function outputScript(outputKey: Uint8Array): Uint8Array {
  if (outputKey.length !== X_ONLY_KEY_BYTES) throw new RangeError(`output key must be ${X_ONLY_KEY_BYTES} bytes`);
  return concatBytes(Uint8Array.of(OP_1, X_ONLY_KEY_BYTES), outputKey);
}
