# ZBTC experiments

Two experiments share this repository:

| Version | Purpose | Status |
| --- | --- | --- |
| [v1](v1/README.md) | Private simulated-note transfers with Groth16 and client-side replay on Bitcoin regtest | Implemented |
| [v2](v2/README.md) | A toy note unlocks a Bitcoin key through AADP and pays native regtest BTC | Planned |

Run each experiment from its own directory. For the existing implementation:

```sh
cd v1
pnpm typecheck
pnpm test:unit
```

The [v1 guide](v1/README.md) contains its setup and demo commands. Its demo resets
its local regtest and wallet directories.
