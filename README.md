# ZBTC experiments

Two approaches live in this Git repository:

| Version | Author | Purpose | Status |
| --- | --- | --- | --- |
| [v1](v1/README.md) | Claude | Private transfers of simulated notes, using Circom/Groth16 and client-side validation anchored on Bitcoin regtest | Implemented |
| [v2](v2/README.md) | Codex | A toy note unlocks a Bitcoin key through AADP, then spends native regtest BTC | Planned |

Run the existing implementation from `v1/`:

```sh
cd v1
pnpm typecheck
pnpm test:unit
```

See the [v1 guide](v1/README.md) for setup and demo commands. Its demo resets its local
regtest and wallet directories.

v2 has no executable implementation yet. Its [plan](v2/docs/codex_plan.md) describes a
deliberately insecure functional demonstration, and its [research notes](v2/docs/research.md)
list the claims, limits and sources behind it.

Existing `node_modules/`, `build/`, `.regtest/` and `.zbtc/` stay at the repository root to
preserve current processes and data; ignored links in `v1/` expose them there. Fresh
checkouts install and generate these files inside `v1/` instead.
