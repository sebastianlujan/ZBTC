// Readers for the demo's JSON artifacts.
//
// bigints travel as decimal strings (JSON numbers lose precision past 2^53)
// and bytes as lowercase hex. Every reader names the offending path, so a
// hand-edited file fails with a precise RangeError instead of a NaN or a
// silently short key.
import { hexToBytes } from '@noble/hashes/utils.js';

export type JsonObject = Readonly<Record<string, unknown>>;

/** Canonical non-negative decimal: no sign, no leading zeros, no exponent. */
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
/** Whole bytes only, lowercase, so one value has exactly one encoding. */
const HEX_PATTERN = /^(?:[0-9a-f]{2})*$/;

export function readObject(value: unknown, path: string): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RangeError(`${path} must be an object`);
  }
  return value as JsonObject;
}

export function readString(value: unknown, path: string): string {
  if (typeof value !== 'string') throw new RangeError(`${path} must be a string`);
  return value;
}

export function readInteger(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new RangeError(`${path} must be an integer`);
  }
  return value;
}

export function readBigInt(value: unknown, path: string): bigint {
  const text = readString(value, path);
  if (!DECIMAL_PATTERN.test(text)) throw new RangeError(`${path} must be a decimal string`);
  return BigInt(text);
}

export function readBytes(value: unknown, path: string): Uint8Array {
  const text = readString(value, path);
  if (!HEX_PATTERN.test(text)) throw new RangeError(`${path} must be lowercase hex`);
  return hexToBytes(text);
}
