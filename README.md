# ZBTC experiments

Two approaches live in this Git repository:

| Version | Author | Purpose | Status |
| --- | --- | --- | --- |
| [v1](v1/README.md) | Claude | Private transfers of simulated notes, using Circom/Groth16 and client-side validation anchored on Bitcoin regtest | Implemented |
| [v2](v2/README.md) | Codex (plan), Claude (code) | A toy note unlocks a Bitcoin key through AADP, then spends native regtest BTC | Implemented |

Each version is its own pnpm package. Run v1 from `v1/`:

```sh
cd v1
pnpm typecheck
pnpm test:unit
```

and v2 from `v2/`:

```sh
cd v2
pnpm install
pnpm test:unit
pnpm demo
```

See the [v1 guide](v1/README.md) and the [v2 guide](v2/README.md) for setup and demo
details. Each demo resets only its own regtest and artifact directories, and they listen on
different RPC ports (18543 and 18643).

v2 is a deliberately insecure functional demonstration. Its [plan](v2/docs/codex_plan.md)
and [research notes](v2/docs/research.md) list the claims, limits, sources and measurements
behind it.

Existing `node_modules/`, `build/`, `.regtest/` and `.zbtc/` stay at the repository root to
preserve current processes and data; ignored links in `v1/` expose them there. Fresh
checkouts install and generate these files inside `v1/` instead.
