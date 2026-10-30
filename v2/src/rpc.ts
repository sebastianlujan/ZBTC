// Minimal bitcoind JSON-RPC client (fetch + cookie auth), copied from v1 and
// trimmed to the calls the v2 demo makes.
//
// Core's JSON writes amounts as BTC decimals. They cross this boundary only
// through satsToBtc and btcToSats, which go through fixed 8-decimal strings,
// so no float arithmetic ever touches an amount.
import { readFileSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_TIMEOUT_MS = 120_000;
/** Characters of a non-JSON HTTP body kept in the error message. */
const ERROR_BODY_PREVIEW_CHARS = 200;
/** One BTC is 10^8 sats. */
const BTC_DECIMALS = 8;
const SATS_PER_BTC = 100_000_000n;

export class RpcError extends Error {
  override readonly name = 'RpcError';

  constructor(
    readonly code: number,
    message: string,
    readonly method: string,
  ) {
    super(`${method}: ${message} (code ${code})`);
  }
}

export interface RpcClientOptions {
  readonly port: number;
  /** bitcoind -datadir; the cookie is read from <datadir>/regtest/.cookie. */
  readonly datadir: string;
  readonly host?: string;
  readonly timeoutMs?: number;
}

// ---- Response shapes (only the fields the demo reads) ----

export interface RpcVout {
  readonly value: number;
  readonly n: number;
  readonly scriptPubKey: { readonly hex: string };
}

export interface RpcTx {
  readonly txid: string;
  readonly vout: readonly RpcVout[];
  readonly confirmations?: number;
  readonly blockhash?: string;
}

export interface MempoolAcceptResult {
  readonly txid: string;
  readonly allowed?: boolean;
  readonly fees?: { readonly base: number };
  readonly 'reject-reason'?: string;
}

// ---- Amounts ----

/** Exact decimal BTC string for Core, e.g. 101000n → "0.00101000". */
export function satsToBtc(sats: bigint): string {
  if (sats < 0n) throw new RangeError('amount must be non-negative');
  const fraction = (sats % SATS_PER_BTC).toString().padStart(BTC_DECIMALS, '0');
  return `${sats / SATS_PER_BTC}.${fraction}`;
}

/** Core never sends more than 8 decimals, so the fixed-point string is exact. */
export function btcToSats(btc: number): bigint {
  if (!Number.isFinite(btc) || btc < 0) throw new RangeError('amount must be a non-negative number');
  return BigInt(btc.toFixed(BTC_DECIMALS).replace('.', ''));
}

// ---- Client ----

export class BitcoinRpc {
  private readonly baseUrl: string;
  private readonly cookieFile: string;
  private readonly timeoutMs: number;
  private nextId = 0;

  constructor(
    private readonly options: RpcClientOptions,
    /** Wallet name for /wallet/<name> scoped calls, if any. */
    readonly walletName?: string,
  ) {
    this.baseUrl = `http://${options.host ?? DEFAULT_HOST}:${options.port}`;
    this.cookieFile = path.join(options.datadir, 'regtest', '.cookie');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** A client whose calls go to /wallet/<name>. */
  wallet(name: string): BitcoinRpc {
    return new BitcoinRpc(this.options, name);
  }

  private auth(): string {
    // Re-read every call: the cookie changes whenever bitcoind restarts.
    const cookie = readFileSync(this.cookieFile, 'utf8').trim();
    return `Basic ${Buffer.from(cookie).toString('base64')}`;
  }

  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const url = this.walletName ? `${this.baseUrl}/wallet/${encodeURIComponent(this.walletName)}` : `${this.baseUrl}/`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: this.auth() },
      body: JSON.stringify({ jsonrpc: '1.0', id: ++this.nextId, method, params }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await response.text();
    let body: { result?: T; error?: { code: number; message: string } | null } | undefined;
    try {
      body = JSON.parse(text);
    } catch {
      throw new RpcError(-response.status, `HTTP ${response.status}: ${text.slice(0, ERROR_BODY_PREVIEW_CHARS)}`, method);
    }
    if (body?.error) throw new RpcError(body.error.code, body.error.message, method);
    if (!response.ok) throw new RpcError(-response.status, `HTTP ${response.status}`, method);
    return body?.result as T;
  }

  // ---- Chain ----
  getBlockchainInfo() {
    return this.call<{ chain: string; blocks: number }>('getblockchaininfo');
  }
  getNetworkInfo() {
    return this.call<{ version: number; subversion: string }>('getnetworkinfo');
  }
  getBlock(hash: string) {
    return this.call<{ hash: string; height: number; tx: string[] }>('getblock', [hash, 1]);
  }

  // ---- Transactions ----
  getRawTransaction(txid: string, verbose: true): Promise<RpcTx>;
  getRawTransaction(txid: string, verbose?: false): Promise<string>;
  getRawTransaction(txid: string, verbose = false) {
    return this.call<RpcTx | string>('getrawtransaction', [txid, verbose]);
  }
  getTxOut(txid: string, vout: number) {
    return this.call<{ value: number; scriptPubKey: { hex: string } } | null>('gettxout', [txid, vout]);
  }
  testMempoolAccept(rawTxs: string[]) {
    return this.call<MempoolAcceptResult[]>('testmempoolaccept', [rawTxs]);
  }
  sendRawTransaction(hex: string) {
    return this.call<string>('sendrawtransaction', [hex]);
  }

  // ---- Descriptors and addresses ----
  getDescriptorInfo(descriptor: string) {
    return this.call<{ descriptor: string; checksum: string }>('getdescriptorinfo', [descriptor]);
  }
  deriveAddresses(descriptor: string) {
    return this.call<string[]>('deriveaddresses', [descriptor]);
  }
  validateAddress(address: string) {
    return this.call<{ isvalid: boolean; scriptPubKey?: string }>('validateaddress', [address]);
  }

  // ---- Mining ----
  generateToAddress(blocks: number, address: string) {
    return this.call<string[]>('generatetoaddress', [blocks, address]);
  }

  // ---- Wallet (call on a wallet-scoped client) ----
  createWallet(name: string) {
    return this.call<{ name: string }>('createwallet', [name]);
  }
  getNewAddress(addressType: 'bech32' | 'bech32m' = 'bech32m') {
    return this.call<string>('getnewaddress', ['', addressType]);
  }
  sendToAddress(address: string, amountSats: bigint) {
    return this.call<string>('sendtoaddress', [address, satsToBtc(amountSats)]);
  }
  getReceivedByAddress(address: string, minimumConfirmations: number) {
    return this.call<number>('getreceivedbyaddress', [address, minimumConfirmations]);
  }
}
