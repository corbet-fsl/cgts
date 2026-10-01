# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. No production source exclusions are currently approved.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

## Emitted source metric

The acceptance metric is now 100% of upstream LLVM LCOV's emitted production
source line counters (DA) and branch counters (BRDA), from the same execution as
the retained raw JSON. This is source coverage, not every generic instantiation.
LLVM JSON and LCOV summary totals can count generic copies differently from
the merged source records. The original JSON checker remains diagnostic code;
its stricter instantiation totals are not described as passed.

The source gate requires a nonempty report, an exact file inventory matching the
companion JSON, matching raw summary metadata, complete emitted branch counts
and no duplicate, unknown or zero counters. It has no production exclusions.
Actual browser/device execution remains separate from native coverage.

## Proposed invariant exceptions

These exact exceptions require independent review. They do not qualify disabled
pin-spend integration. Each is bound to complete local source. Proofs that depend on CRBK or CGRD
additionally bind that exact crate identity in the retained Cargo.lock; the checker
requires exactly one matching package/version/full Git source. A change to the
actual proof dependency requires review. Other dependency updates still undergo
the complete real CI suite, without invalidating an unrelated immutable-type proof.
JSON, LCOV and annotated source inventories must agree before exclusions; every
emitted line/arm must still exist and remain unexecuted. Real imported scan-plan,
subject/level corruption, signed expiry, duplicate receipt and leaf refusal cases
have no exceptions.

- `gates.rs`, the `define_settings` error mapper: the exclusive mutable Rulebook
  reference was checked for an absent key. The fixed key `voucher.validity_days`
  and fixed integer definition (default30, inclusive1..365, technical/community)
  pass crbk's key and Setting validators. The locked `Rulebook::define` has only
  those validation failures and duplicate-key refusal, with no I/O or concurrent
  mutation. The mapper is defensive against future upstream changes.
- `gates.rs`, the admitted profile community comparison's false arm: before
  calling cgrd, this adapter checks policy.community equals snapshot.community.
  The locked cgrd `guard.rs::evaluate_authenticated` refuses a credential whose
  community differs from that same policy, then returns credential.community in
  Admission::Admitted. No mutable or deserialized admission enters this port.
  Different member, public/full scope, invalid signature and configured community
  refusal are all actually tested. The remaining member/scope arms are gated.
- `passport.rs`, the expired-capability predicate's true arm: the sole constructor
  `verify_passport` requires valid_until > checked_at before the real stateful
  proof verifier. Both fields are private and immutable. `gates` first requires
  checked_at == context.now, so its following expiry predicate cannot be true.
  Real expired BBS+ presentation, replay, wrong community/subject/epoch and changed
  check time are refused by actual tests. No bare pseudonym can create a witness.
- `pins.rs`, all seven emitted lines of PinSpendVerifier::verify_spent: invoking
  it requires a reference to SpentChange. That type has one private sealed field,
  no constructor, deserializer or other accepting conversion. Both public
  verification entry points return ExtensionsUnavailable after validating the
  binding. This disabled path cannot be invoked by safe production callers.
  Public refusal and compile-fail capability boundaries remain tested. We do not
  fabricate a witness, enable an issuer harness, or claim atomic pin replacement
  acceptance. Once the accounting owner supplies genuine verified extension
  acceptance, these exceptions must be removed and the real round trip must pass.

The first-party dependency declarations still follow main and retain one source
revision per crate. The exception hashes are evidence checks, not immutable Git
rev declarations or permission to ignore updates. A green adjusted metric means
all non-excluded production locations executed; mandatory review and the sealed
G2 integration blocker remain separate acceptance requirements.

The shared checker now has17 regression methods, including changed, duplicate,
missing and malformed proof dependencies and independent unrelated lock updates.
These revision-bound evidence assertions qualify exceptions only; Cargo manifests
still follow main and the first-party policy still requires one revision per crate.
