// Minimal bitcoind JSON-RPC client (fetch + cookie auth) and the envelope
// publication chain:
//   createrawtransaction [] [{"data": hex}] -> fundrawtransaction (fee wallet)
//   -> signrawtransactionwithwallet -> sendrawtransaction
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { bytesToHex } from './crypto.js';

// bitcoind RPC error codes ZBTC reacts to (bitcoin/src/rpc/protocol.h).
/** createwallet on an existing wallet ("Database already exists"). */
export const RPC_WALLET_ERROR = -4;
/** Unknown block hash. */
export const RPC_INVALID_ADDRESS_OR_KEY = -5;
/** Block height out of range. */
export const RPC_INVALID_PARAMETER = -8;
export const RPC_WALLET_ALREADY_LOADED = -35;

export class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly method: string,
  ) {
    super(`${method}: ${message} (code ${code})`);
    this.name = 'RpcError';
  }
}

export interface RpcClientOptions {
  /** RPC port on 127.0.0.1. */
  port: number;
  /** bitcoind -datadir; the cookie is read from <datadir>/regtest/.cookie. */
  datadir?: string;
  /** Explicit cookie file (overrides datadir). */
  cookieFile?: string;
  host?: string;
  /** Per-call timeout (ms). */
  timeoutMs?: number;
}

// ---- Response shapes (only the fields ZBTC uses) ----

export interface RpcVout {
  value: number;
  n: number;
  scriptPubKey: { hex: string; type?: string; asm?: string; address?: string };
}

export interface RpcVin {
  txid?: string;
  vout?: number;
  coinbase?: string;
}

export interface Outpoint {
  txid: string;
  vout: number;
}

export interface RpcTx {
  txid: string;
  hash: string;
  vsize?: number;
  vin: RpcVin[];
  vout: RpcVout[];
  hex?: string;
}

export interface RpcBlock {
  hash: string;
  height: number;
  previousblockhash?: string;
  tx: RpcTx[];
}

export interface MempoolAcceptResult {
  txid: string;
  wtxid?: string;
  allowed?: boolean;
  vsize?: number;
  'reject-reason'?: string;
  'reject-details'?: string;
}

export class BitcoinRpc {
  private readonly baseUrl: string;
  private readonly cookieFile: string;
  private readonly timeoutMs: number;
  private nextId = 0;

  constructor(
    private readonly opts: RpcClientOptions,
    /** Wallet name for /wallet/<name> scoped calls, if any. */
    readonly walletName?: string,
  ) {
    const host = opts.host ?? '127.0.0.1';
    this.baseUrl = `http://${host}:${opts.port}`;
    if (opts.cookieFile) this.cookieFile = opts.cookieFile;
    else if (opts.datadir) this.cookieFile = path.join(opts.datadir, 'regtest', '.cookie');
    else throw new Error('BitcoinRpc needs datadir or cookieFile');
    this.timeoutMs = opts.timeoutMs ?? 120_000;
  }

  /** A client whose calls go to /wallet/<name>. */
  wallet(name: string): BitcoinRpc {
    return new BitcoinRpc(this.opts, name);
  }

  private auth(): string {
    // Re-read every call: the cookie changes whenever bitcoind restarts.
    const cookie = readFileSync(this.cookieFile, 'utf8').trim();
    return 'Basic ' + Buffer.from(cookie).toString('base64');
  }

  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const url = this.walletName
      ? `${this.baseUrl}/wallet/${encodeURIComponent(this.walletName)}`
      : `${this.baseUrl}/`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: this.auth() },
      body: JSON.stringify({ jsonrpc: '1.0', id: ++this.nextId, method, params }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    let body: { result?: T; error?: { code: number; message: string } | null } | undefined;
    try {
      body = JSON.parse(text);
    } catch {
      throw new RpcError(-res.status, `HTTP ${res.status}: ${text.slice(0, 200)}`, method);
    }
    if (body?.error) throw new RpcError(body.error.code, body.error.message, method);
    if (!res.ok) throw new RpcError(-res.status, `HTTP ${res.status}`, method);
    return body?.result as T;
  }

  // ---- Chain ----
  getBlockchainInfo() {
    return this.call<{ chain: string; blocks: number; bestblockhash: string }>('getblockchaininfo');
  }
  getBlockCount() {
    return this.call<number>('getblockcount');
  }
  getBlockHash(height: number) {
    return this.call<string>('getblockhash', [height]);
  }
  getBestBlockHash() {
    return this.call<string>('getbestblockhash');
  }
  getBlock(hash: string, verbosity: 2 = 2) {
    return this.call<RpcBlock>('getblock', [hash, verbosity]);
  }
  invalidateBlock(hash: string) {
    return this.call<null>('invalidateblock', [hash]);
  }
  reconsiderBlock(hash: string) {
    return this.call<null>('reconsiderblock', [hash]);
  }

  // ---- Mempool / transactions ----
  getRawMempool() {
    return this.call<string[]>('getrawmempool');
  }
  testMempoolAccept(rawTxs: string[]) {
    return this.call<MempoolAcceptResult[]>('testmempoolaccept', [rawTxs]);
  }
  sendRawTransaction(hex: string) {
    return this.call<string>('sendrawtransaction', [hex]);
  }
  getRawTransaction(txid: string, verbose: true): Promise<RpcTx>;
  getRawTransaction(txid: string, verbose?: false): Promise<string>;
  getRawTransaction(txid: string, verbose = false) {
    return this.call<RpcTx | string>('getrawtransaction', [txid, verbose]);
  }
  decodeRawTransaction(hex: string) {
    return this.call<RpcTx & { vsize: number; size: number; weight: number }>('decoderawtransaction', [hex]);
  }

  // ---- Mining ----
  generateToAddress(n: number, address: string) {
    return this.call<string[]>('generatetoaddress', [n, address]);
  }
  /** Mines one block with exactly these txs (raw hex or mempool txids), in order. */
  generateBlock(output: string, rawTxsOrTxids: string[], submit = true) {
    return this.call<{ hash: string; hex?: string }>('generateblock', [output, rawTxsOrTxids, submit]);
  }

  // ---- Wallet (call on a wallet-scoped client) ----
  createWallet(name: string) {
    return this.call<{ name: string }>('createwallet', [name]);
  }
  getNewAddress() {
    return this.call<string>('getnewaddress');
  }
  sendToAddress(address: string, btc: number) {
    return this.call<string>('sendtoaddress', [address, btc]);
  }
  /** Loads a wallet; a wallet that is already loaded is not an error. */
  async loadWallet(name: string): Promise<void> {
    try {
      await this.call('loadwallet', [name]);
    } catch (e) {
      if (!(e instanceof RpcError && e.code === RPC_WALLET_ALREADY_LOADED)) throw e;
    }
  }
  /** lockunspent; unlock = true releases the outpoints. */
  lockUnspent(unlock: boolean, outpoints: Outpoint[]) {
    return this.call<boolean>('lockunspent', [unlock, outpoints]);
  }
  listLockUnspent() {
    return this.call<Outpoint[]>('listlockunspent');
  }
}

// ---- Envelope publication ----

export interface EnvelopeTx {
  txid: string;
  hex: string;
  vsize: number;
  /** Fee-wallet coins spent by the carrier (they link publications on-chain). */
  inputs: Outpoint[];
}

export interface BuildEnvelopeOptions {
  /**
   * Lock the selected coins in the fee wallet (in memory) so that another tx
   * built before this one is mined cannot pick the same inputs. Default true.
   */
  lockUnspents?: boolean;
}

/**
 * Builds and signs (but does not send) a tx whose only non-change output is
 * OP_RETURN <envelope>, funded by `walletName`.
 */
export async function buildEnvelopeTx(
  rpc: BitcoinRpc,
  walletName: string,
  bytes: Uint8Array,
  opts: BuildEnvelopeOptions = {},
): Promise<EnvelopeTx> {
  const w = rpc.wallet(walletName);
  const raw = await rpc.call<string>('createrawtransaction', [[], [{ data: bytesToHex(bytes) }]]);
  const funded = await w.call<{ hex: string }>('fundrawtransaction', [
    raw,
    { lockUnspents: opts.lockUnspents ?? true },
  ]);
  const signed = await w.call<{ hex: string; complete: boolean }>('signrawtransactionwithwallet', [funded.hex]);
  if (!signed.complete) throw new Error('signrawtransactionwithwallet: incomplete');
  const decoded = await rpc.decodeRawTransaction(signed.hex);
  const inputs = decoded.vin.map((i) => ({ txid: i.txid as string, vout: i.vout as number }));
  return { txid: decoded.txid, hex: signed.hex, vsize: decoded.vsize, inputs };
}

/** sendrawtransaction of a built carrier; throws unless bitcoind returns its txid. */
export async function sendEnvelopeTx(rpc: BitcoinRpc, tx: EnvelopeTx): Promise<void> {
  const txid = await rpc.sendRawTransaction(tx.hex);
  if (txid !== tx.txid) throw new Error(`sendrawtransaction returned ${txid}, expected ${tx.txid}`);
}

/** buildEnvelopeTx + sendrawtransaction. */
export async function publishEnvelope(rpc: BitcoinRpc, walletName: string, bytes: Uint8Array): Promise<EnvelopeTx> {
  const tx = await buildEnvelopeTx(rpc, walletName, bytes);
  await sendEnvelopeTx(rpc, tx);
  return tx;
}
