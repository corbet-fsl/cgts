# cgts implemented contract

cgts verifies community gates and global passport presentations. cplc alone
owns the admission decision over these witnesses and its authenticated current
settings publication. cgts has no production `decide` or rulebook evaluator.

## Verified inputs and legal veto

The service authenticates the member and selects trusted gate implementations,
provider keys, clock, storage and clbs authority verifier. Implementing those
traits is privileged; they are not request bodies. `run` checks the exact gate
and provider switches and the mandatory legal veto before verification, then
rechecks legal state before committing. Missing/null/false switches disable a
gate. Errors never grant access or expose raw evidence.

`CheckedGate` has private community, pseudonym, action, revision, effective
community epoch and transient check-time bindings. `check` validates those
bindings, combines fresh checks with retained facts and returns `CheckedGates`
only after a live legal check, including for an empty collection. Duplicate fresh
gate identities are refused. A fresh fact replaces its retained counterpart.
`in_context` refuses mismatched bindings. Plain wire results cannot construct
these capabilities. Maximum-proof-age policy fails closed because five-field
gate metadata has no authenticated proof time.

`verify_passport` calls the real stateful cpsd BBS+ verifier and consumes its
challenge before returning `VerifiedPassport`. A bare pseudonym is insufficient.
The service supplies the current authenticated global epoch; suspension therefore
invalidates the old passport at the next verification/renewal. The witness binds
global gates to that verified community pseudonym, the action and cplc's effective
community epoch. It requires a shared cohort expiry at a UTC-day boundary.
Global facts and holder identifiers are never persisted by cgts. The global epoch
and effective community epoch are independent counters with different owners.

`GateResult` serializes only gate, level, pseudonym, provider and exclusive
validity. Its Debug implementation is redacted. `collect` is a read of current,
enabled, unexpired retained community facts. `withdraw` is a privileged provider
revocation operation; endpoint authentication and authorization belong to the
service. It never deletes spent markers. No facade logs or traces requests.

## Leaf adapters

Voucher signatures bind community and intended member through cvch's signed
member binding. The sponsor's precise redemption deadline is used only during
verification. Retained validity comes from `voucher.validity_days`, a crbk
community technical setting (default 30, range 1–365), rounded to the UTC day.
`gates::define_settings` installs its catalogue entry. An intercepted voucher
cannot burn another member's receipt. The permanent opaque receipt marker and
result update commit atomically; failure rolls back both. No sponsor identity,
voucher ID, signature or redemption time is retained.

ProfileGate delegates signed v2 profile and pin opening checks to cgrd. The
verifier's minimum epoch must cover the effective epoch from cplc's verified
settings. A check is transient and expires one second later: this protocol
precision binds the current profile operation and is never persisted. It cannot
become a reusable badge after a profile edit. A public projection cannot satisfy
a full-profile requirement.

BalanceGate and RecordGate pin the current reviewed cblc stack, but the runner
refuses the reserved `cblc` gate with `ExtensionsUnavailable` before invoking any
provider. Signed acceptance alone is insufficient to prove the complete private
extension relation. There is no feature that bypasses this guard. The extension
circuit and its proof tests must be complete before activation. No successful
balance change permission can currently be minted by these adapters.

LegalGate delegates exact-action checks to clbs. It applies even when action
policy is empty and cannot be disabled by a rulebook switch. Legal errors fail
closed. Qualified authority verification remains a service/leaf responsibility.

The development gate exists only in cglb. cgts exports no development module in
any build; CI verifies absence in a release profile with debug assertions enabled.

## Persistence

The service owns one crlt pool, credentials and migration history. `MemoryStore`
and `LibsqlStore` implement the same atomic claim/result contract. Install `SCHEMA`
and `clbs::SCHEMA` with service-assigned migration numbers.

| Table | Content | Primary key |
|---|---|---|
| cgts_results | Current community gate/provider/expiry for a pseudonym | community_id, subject, gate, provider |
| cgts_spent | Opaque leaf-domain single-use marker | community_id, domain, marker |

Tables are WITHOUT ROWID and every query is checked by crlt for an index-backed
plan. Deploy one database per community; composite keys additionally isolate
shared-file tests. Replacement keeps no history. Spent markers deliberately have
no subject or time, survive restart and are permanent while vouchers/spends can
be replayed. Capacity planning must include these permanent anti-replay rows.
Raw database administration is trusted. Reads return complete results or errors.

## Validation

GitHub Actions runs formatting, strict Clippy, native and release tests, real
libSQL round trips, rollback/concurrency/restart checks, signed vouchers, signed
v2 profile fixtures, real BBS+ blind issuance and authenticated presentation,
legal vetoes and compile-fail capability boundaries. It also rejects floating or
duplicated corbet dependency revisions in Cargo.lock and cargo metadata. The
optional live Turso test uses a disposable database only when credentials are
provided. No Cargo runs on the workstation.

Checked receipts bind the complete resolved setting values and authenticated
publication issuance time as well as revision/epoch. Reusing a revision while
changing a gate parameter cannot transplant a receipt into cplc's publication.
These bindings are transient and never written to the gate result tables.

The production pin adapter is `pins::PinSpendVerifier`, with the opaque
`pins::SpentChange` token. `pins::change_binding` delegates the complete transition
to cblc's canonical framing. `verify_pin_change` currently returns
`ExtensionsUnavailable`; no accepting token constructor exists. cmbr wires this
adapter directly into cpns's authorized compare-and-exchange, so neither an
unspent token nor a caller-built signed receipt can alter a pin. Balance and
record adapters themselves also refuse, even when called outside Gatekeeper.
Positive extension-spend/restart tests cannot honestly pass until cblc's private
extension circuit is proven; the current tests require refusal for all contexts.

All retained provider expiries are rounded down to UTC days before constructing
CheckedGate or committing a claim. Evidence that cannot reach the next day cannot
be retained. Both store adapters and the SQL constraint reject precise retained
expiries. Transient profile checks keep second precision because they certify the
current signed profile at the verification instant and are never persisted.
