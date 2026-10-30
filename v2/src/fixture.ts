// The frozen experiment (P00): everything a setup needs to replay one run bit
// for bit, plus the public Bitcoin terms the envelope authenticates: the block
// snapshot that confirmed the funding, the funding outpoint and the recipient.
//
// Data flow: createFixture → serializeFixture → fixture.json. parseFixture
// reads it back and refuses any file that breaks the demo's invariants (seed
// width, balanced amounts, note pays exactly the payment). envelopeAssociatedData
// selects the public part, never the seed or the opening, for the AEAD.
//
// The setup operator is trusted: the fixture holds known test secrets.
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  BASE_FIELD_MODULUS,
  BLOCK_HASH_BYTES,
  ENVELOPE_AD_DOMAIN,
  FEE_SATS,
  FIXTURE_VERSION,
  FUNDING_SATS,
  PAYMENT_SATS,
  SETUP_SEED_BYTES,
  TXID_BYTES,
} from './constants.js';
import {
  formatJson,
  readBigInt,
  readBytes,
  readInteger,
  readObject,
  readString,
  type JsonObject,
} from './json.js';
import { issueNote, TOY_NOTE_OPENING, type NoteOpening } from './note.js';

export interface Manifest {
  readonly nodeVersion: string;
  readonly bitcoinCoreVersion: string;
}

/** The chain state the fixture is frozen at: the block that confirmed the funding transaction. */
export interface BlockSnapshot {
  /** Lowercase hex in the byte order Core displays. */
  readonly blockHash: string;
  readonly height: number;
}

export interface Outpoint {
  /** Lowercase hex in the byte order Core displays. */
  readonly txid: string;
  readonly vout: number;
}

export interface SpendTerms {
  readonly fundingOutpoint: Outpoint;
  readonly recipientScript: Uint8Array;
  readonly fundingSats: bigint;
  readonly paymentSats: bigint;
  readonly feeSats: bigint;
}

export interface Fixture {
  readonly version: number;
  readonly manifest: Manifest;
  readonly seed: Uint8Array;
  readonly note: NoteOpening;
  readonly snapshot: BlockSnapshot;
  readonly spend: SpendTerms;
}

export interface FixtureInputs {
  readonly seed: Uint8Array;
  readonly manifest: Manifest;
  readonly snapshot: BlockSnapshot;
  readonly fundingOutpoint: Outpoint;
  readonly recipientScript: Uint8Array;
}

const TXID_PATTERN = new RegExp(`^[0-9a-f]{${2 * TXID_BYTES}}$`);
const BLOCK_HASH_PATTERN = new RegExp(`^[0-9a-f]{${2 * BLOCK_HASH_BYTES}}$`);
/** vout is a u32 on the wire. */
const MAX_VOUT = 0xffff_ffff;

// ---- Construction ----

/** The toy note and the demo amounts around the caller's seed and Bitcoin terms. */
export function createFixture({ seed, manifest, snapshot, fundingOutpoint, recipientScript }: FixtureInputs): Fixture {
  const fixture: Fixture = {
    version: FIXTURE_VERSION,
    manifest,
    seed,
    note: TOY_NOTE_OPENING,
    snapshot,
    spend: { fundingOutpoint, recipientScript, fundingSats: FUNDING_SATS, paymentSats: PAYMENT_SATS, feeSats: FEE_SATS },
  };
  assertValidFixture(fixture);
  return fixture;
}

// ---- Invariants ----

function assertValidSnapshot({ blockHash, height }: BlockSnapshot): void {
  if (!BLOCK_HASH_PATTERN.test(blockHash)) {
    throw new RangeError(`block hash must be ${2 * BLOCK_HASH_BYTES} lowercase hex characters`);
  }
  if (!Number.isInteger(height) || height < 0) throw new RangeError('block height must be a non-negative integer');
}

function assertValidOutpoint({ txid, vout }: Outpoint): void {
  if (!TXID_PATTERN.test(txid)) throw new RangeError(`txid must be ${2 * TXID_BYTES} lowercase hex characters`);
  if (!Number.isInteger(vout) || vout < 0 || vout > MAX_VOUT) throw new RangeError('vout must be a u32');
}

/** One input, one recipient output, no change: whatever the payment leaves is the fee. */
function assertBalancedSpend({ fundingSats, paymentSats, feeSats, recipientScript }: SpendTerms): void {
  if (recipientScript.length === 0) throw new RangeError('recipient script must not be empty');
  if (paymentSats <= 0n || feeSats < 0n) throw new RangeError('payment must be positive and fee non-negative');
  if (fundingSats !== paymentSats + feeSats) throw new RangeError('funding must equal payment plus fee');
}

function assertValidFixture(fixture: Fixture): void {
  if (fixture.version !== FIXTURE_VERSION) throw new RangeError(`unsupported fixture version ${fixture.version}`);
  if (fixture.seed.length !== SETUP_SEED_BYTES) throw new RangeError(`seed must be ${SETUP_SEED_BYTES} bytes`);
  assertValidSnapshot(fixture.snapshot);
  assertValidOutpoint(fixture.spend.fundingOutpoint);
  assertBalancedSpend(fixture.spend);
  if (issueNote(fixture.note).exitAmount !== fixture.spend.paymentSats) {
    throw new RangeError('the note must pay out exactly the payment amount');
  }
}

// ---- JSON ----

export function serializeFixture({ version, manifest, seed, note, snapshot, spend }: Fixture): string {
  const json = {
    version,
    manifest,
    seed: bytesToHex(seed),
    note: { ownerKey: `${note.ownerKey}`, rho: `${note.rho}`, amount: `${note.amount}` },
    snapshot,
    spend: {
      fundingOutpoint: spend.fundingOutpoint,
      recipientScript: bytesToHex(spend.recipientScript),
      fundingSats: `${spend.fundingSats}`,
      paymentSats: `${spend.paymentSats}`,
      feeSats: `${spend.feeSats}`,
    },
  };
  return formatJson(json);
}

function parseSpend(spend: JsonObject): SpendTerms {
  const outpoint = readObject(spend.fundingOutpoint, 'spend.fundingOutpoint');
  return {
    fundingOutpoint: {
      txid: readString(outpoint.txid, 'spend.fundingOutpoint.txid'),
      vout: readInteger(outpoint.vout, 'spend.fundingOutpoint.vout'),
    },
    recipientScript: readBytes(spend.recipientScript, 'spend.recipientScript'),
    fundingSats: readBigInt(spend.fundingSats, 'spend.fundingSats'),
    paymentSats: readBigInt(spend.paymentSats, 'spend.paymentSats'),
    feeSats: readBigInt(spend.feeSats, 'spend.feeSats'),
  };
}

/** Throws RangeError for a malformed file or one that breaks a fixture invariant. */
export function parseFixture(text: string): Fixture {
  const root = readObject(JSON.parse(text), 'fixture');
  const manifest = readObject(root.manifest, 'manifest');
  const note = readObject(root.note, 'note');
  const snapshot = readObject(root.snapshot, 'snapshot');
  const fixture: Fixture = {
    version: readInteger(root.version, 'version'),
    manifest: {
      nodeVersion: readString(manifest.nodeVersion, 'manifest.nodeVersion'),
      bitcoinCoreVersion: readString(manifest.bitcoinCoreVersion, 'manifest.bitcoinCoreVersion'),
    },
    seed: readBytes(root.seed, 'seed'),
    note: {
      ownerKey: readBigInt(note.ownerKey, 'note.ownerKey'),
      rho: readBigInt(note.rho, 'note.rho'),
      amount: readBigInt(note.amount, 'note.amount'),
    },
    snapshot: {
      blockHash: readString(snapshot.blockHash, 'snapshot.blockHash'),
      height: readInteger(snapshot.height, 'snapshot.height'),
    },
    spend: parseSpend(readObject(root.spend, 'spend')),
  };
  assertValidFixture(fixture);
  return fixture;
}

// ---- Envelope binding ----

/**
 * Canonical bytes of the fixture's public terms. The object is built field by
 * field, so its key order (and therefore its bytes) never depends on input.
 * AEAD authenticates these terms; it does not make them part of the AADP relation.
 */
export function envelopeAssociatedData({ version, note, snapshot, spend }: Fixture): Uint8Array {
  const issued = issueNote(note);
  const binding = {
    domain: ENVELOPE_AD_DOMAIN,
    version,
    fieldModulus: `${BASE_FIELD_MODULUS}`,
    note: {
      ownerTag: `${issued.ownerTag}`,
      noteCommitment: `${issued.noteCommitment}`,
      nullifierTag: `${issued.nullifierTag}`,
      exitAmount: `${issued.exitAmount}`,
    },
    snapshot: { blockHash: snapshot.blockHash, height: snapshot.height },
    fundingOutpoint: { txid: spend.fundingOutpoint.txid, vout: spend.fundingOutpoint.vout },
    recipientScript: bytesToHex(spend.recipientScript),
    amounts: { fundingSats: `${spend.fundingSats}`, paymentSats: `${spend.paymentSats}`, feeSats: `${spend.feeSats}` },
  };
  return utf8ToBytes(JSON.stringify(binding));
}
