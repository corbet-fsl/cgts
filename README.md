# cgts

Community gatekeeping for `cvld`: run gates, collect proof metadata, expose
headless steps, and combine rulebook decisions with the mandatory legal veto.
Native Rust, FSL-1.1-ALv2. Development API; never publish to a registry.

`Gatekeeper::{steps,run,collect,check,withdraw}` operates within one community.
`Gate` has a typed transient input; its result contains only gate, level,
subject, provider and exclusive expiry. `VoucherGate`, `ProfileGate`,
`BalanceGate`, `RecordGate` and `LegalGate` adapt the existing leaves. Balance
and record execution is disabled with an explicit error until cblc extension
proofs are established. The global toy test gate belongs only to cglb; cgts has no always-pass implementation. See [the implemented contract](docs/CONTRACT.md).

The service supplies an authenticated active `crbk::Snapshot`, subject, action,
clock and leaf configuration. Inactive gates/providers never appear in steps
and never execute. `clbs` applies before each action regardless of rulebook
switches. Profile checks and balance spends are transient; vouchers can be
retained. Only current metadata and opaque spent markers reach storage.

## Dependency survey

Checked crates.io and GitHub sources on 2026-09-30; direct cvld dependencies
are pinned by full Git revision in Cargo.toml. Read each available leaf README
and contract before integration.

| Candidate | Choice and reason |
|---|---|
| [crlt](https://github.com/corbet-foss/crlt) / [official libsql](https://github.com/tursodatabase/libsql) | crlt main exposes scoped transactions, migrations and enforced indexed plans. Use it exclusively; no direct-driver fallback is necessary. |
| [crbk](https://github.com/corbet-foss/crbk) | Existing switches, snapshot types and policy evaluator. Compose its decisions instead of implementing all/any/k-of-n again. |
| [clbs](https://github.com/corbet-foss/clbs) | Existing community legal-order and self-ban semantics; always consult its exact-action API. |
| [cgrd](https://github.com/corbet-foss/cgrd) | Existing signed person/profile validation and pin checks. Disable its optional storage; do not retain profiles. |
| [cvch](https://github.com/corbet-foss/cvch) | Existing voucher signature, scope, expiry and receipt computation. Add only its explicitly host-owned atomic storage. This revision has no docs/CONTRACT.md; use its README and documented Rust API. |
| [cblc](https://github.com/corbet-libs/cblc) | Available under corbet-libs, FSL, rather than corbet-foss. Verify signed extended change-spend acceptances and run fresh forum-listing/first-contact record checks without duplicating accounting or proof logic. It composes LGPL [cssr](https://github.com/corbet-foss/cssr), [cvfy](https://github.com/corbet-foss/cvfy) and [czkp](https://github.com/corbet-foss/czkp). |
| [Cedar](https://github.com/cedar-policy/cedar) 4.13 / crates.io `gate` 0.6.3 | Cedar is a maintained general authorization language, broader than this facade and redundant with crbk. The `gate` crate is a game library. Neither replaces domain leaf composition. |
| [Serde](https://github.com/serde-rs/serde), serde_json, thiserror | Maintained encoding and redacted errors. No custom serialization parser. |
| [async-trait](https://github.com/dtolnay/async-trait) | Considered; native Rust future-returning traits suffice, avoiding allocation/dynamic dispatch. |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | Only the cvch configuration key type and real test signatures; no local crypto implementation. |

External dependencies are MIT, Apache-2.0 or BSD-3-Clause; sibling leaves use
LGPL with their linking exception. No GPL-only or AGPL-only dependency is added.
Test-only csgn parses cgrd's frozen public signing vector at its matching pinned
wire revision. Tokio runs synchronous cblc verification on a blocking thread;
tempfile and data-encoding support real database and signed balance tests.
Cargo.lock pins transitive upstream branch dependencies, including cssr, cvfy
and czkp. CI uses --locked and retains the lockfile for reproducibility.

## Storage and validation

Apply `cgts::SCHEMA` and `clbs::SCHEMA` in the service's complete crlt migration
history, then construct community-bound stores over its existing database pool.
Deploy one database per community; every table also has a composite community
key. `Storage` has real `MemoryStore` and `LibsqlStore` implementations. A voucher
receipt and result commit atomically. Replays are refused, including after reopen.

GitHub Actions runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` and release tests. No Cargo commands run on the workstation.
An optional real-Turso test reads TURSO_URL/TURSO_TOKEN only when both are nonempty;
it writes isolated test rows to a disposable database. Credentials are never
committed or configured in public CI.

## Remaining integration boundaries

The pinned cblc now supplies its extension circuit, holder and real proof tests.
The facade's balance and spent-pin adapters remain disabled until their verified
acceptances are wired into the atomic field-change flow. Signed acceptance tests
here exercise binding and replay protection, not hidden balance mathematics. Fresh record
checks delegate to cblc, including below-quorum proof requirements. Additional
balance predicates need leaf APIs. Field-change execution must coordinate consumption
with cpns. The default cgrd contact detector fails closed where required; a
custom detector adapter is not yet exposed here. Services own authenticated
snapshots, fresh clocks and trust roots. See the contract for precise limits.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
