// The frozen fixture: JSON round trip, the invariants parseFixture enforces,
// and the public-only envelope binding.
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { envelopeAssociatedData, parseFixture, serializeFixture } from '../../src/fixture.js';
import { PLACEHOLDER_RECIPIENT_SCRIPT, PLACEHOLDER_TXID, TEST_SEED, testFixture } from '../helpers/fixture.js';

// Raw JSON edits model a hand-edited file, so the shape is deliberately untyped.
type RawFixture = any;

function editedFixture(edit: (json: RawFixture) => void): string {
  const json: RawFixture = JSON.parse(serializeFixture(testFixture()));
  edit(json);
  return JSON.stringify(json);
}

function boundText(fixture = testFixture()): string {
  return new TextDecoder().decode(envelopeAssociatedData(fixture));
}

describe('fixture JSON', () => {
  it('round-trips with bigints and bytes intact', () => {
    const fixture = testFixture();
    expect(parseFixture(serializeFixture(fixture))).toEqual(fixture);
  });

  it.each<[string, (json: RawFixture) => void]>([
    ['an unknown version', (json) => (json.version = 2)],
    ['a short seed', (json) => (json.seed = json.seed.slice(2))],
    ['an uppercase txid', (json) => (json.spend.fundingOutpoint.txid = PLACEHOLDER_TXID.toUpperCase())],
    ['a negative vout', (json) => (json.spend.fundingOutpoint.vout = -1)],
    ['an amount written as a JSON number', (json) => (json.spend.paymentSats = 100_000)],
    ['a fee that unbalances the spend', (json) => (json.spend.feeSats = '999')],
    ['a note that pays out a different amount', (json) => (json.note.amount = '99999')],
  ])('rejects %s', (_, edit) => {
    expect(() => parseFixture(editedFixture(edit))).toThrow(RangeError);
  });

  it('refuses to create a fixture with a short seed', () => {
    expect(() => testFixture({ seed: TEST_SEED.slice(1) })).toThrow(RangeError);
  });
});

describe('envelope associated data', () => {
  it('is deterministic', () => {
    expect(envelopeAssociatedData(testFixture())).toEqual(envelopeAssociatedData(testFixture()));
  });

  it('binds the funding outpoint and the recipient', () => {
    const otherOutpoint = testFixture({ fundingOutpoint: { txid: PLACEHOLDER_TXID, vout: 1 } });
    const otherRecipient = testFixture({ recipientScript: PLACEHOLDER_RECIPIENT_SCRIPT.slice(1) });
    expect(boundText(otherOutpoint)).not.toBe(boundText());
    expect(boundText(otherRecipient)).not.toBe(boundText());
  });

  it('never includes the setup seed', () => {
    expect(boundText()).not.toContain(bytesToHex(TEST_SEED));
  });
});
