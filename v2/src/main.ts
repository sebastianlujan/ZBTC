// Entry point for `pnpm demo`; scripts/demo.sh starts the regtest node first.
//
// Reads the node's port and datadir from the environment, runs the pipeline,
// writes the artifacts and exits non-zero unless every check passed.
import { ciphertextBytes } from './aadp.js';
import { writeArtifacts } from './artifacts.js';
import { failedChecks, runDemo, type DemoResult } from './demo.js';
import { BitcoinRpc } from './rpc.js';

/** Away from Core's 18443 and v1's 18543, so the two demos never share a node. */
const DEFAULT_RPC_PORT = 18643;
const DEFAULT_DATADIR = '.regtest';
const ARTIFACT_DIRECTORY = '.demo';

function printSummary({ fixture, prepared, broadcast, checks }: DemoResult): void {
  const { txid, vout } = fixture.spend.fundingOutpoint;
  console.log(`snapshot:         block ${fixture.snapshot.height} ${fixture.snapshot.blockHash}`);
  console.log(`funding outpoint: ${txid}:${vout}`);
  console.log(`setup attempt:    ${prepared.setupAttempt} (cofactor nonzero)`);
  console.log(`ciphertext:       ${ciphertextBytes(prepared.ciphertext)} bytes`);
  console.log(`spend txid:       ${broadcast.localTxid}`);
  for (const [name, passed] of Object.entries(checks)) console.log(`${passed ? 'OK  ' : 'FAIL'} ${name}`);
  console.log(`artifacts:        ${ARTIFACT_DIRECTORY}/`);
}

async function main(): Promise<void> {
  const port = Number(process.env.RPCPORT ?? DEFAULT_RPC_PORT);
  const rpc = new BitcoinRpc({ port, datadir: process.env.DATADIR ?? DEFAULT_DATADIR });
  const result = await runDemo(rpc);
  writeArtifacts(ARTIFACT_DIRECTORY, result);
  printSummary(result);
  if (failedChecks(result.checks).length > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
