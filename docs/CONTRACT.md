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
gate/level/provider identities are refused. A fresh fact replaces only its retained
counterpart from the same provider; other authenticated providers remain available
for provider-specific requirements without increasing distinct-gate thresholds.
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

The voucher gate presents a cvch link (`cvch::link::Request`) to the service's
link store. The store owns the number of uses and holds no issuer; the notice
sealed to the issuer's device is relayed opaque. A link that waits for the
issuer's sign-off is `Error::Pending` and the member presents it again for the
decision. Retained validity comes from `voucher.validity_days`, a crbk
community technical setting (default 30, range 1-365), rounded to the UTC day.
`gates::define_settings` installs its entry and `voucher.sponsor_visible`,
which only devices read. The permanent opaque claim marker (hash of link id and
member) and the result update commit atomically; failure rolls back both, so a
person is proven once per link and an interrupted commit can be retried.

ProfileGate delegates signed v2 profile and pin opening checks to cgrd. The
verifier's minimum epoch must cover the effective epoch from cplc's verified
settings. A check is transient and expires one second later: this protocol
precision binds the current profile operation and is never persisted. It cannot
become a reusable badge after a profile edit. A public projection cannot satisfy
a full-profile requirement.

BalanceGate and RecordGate follow the current cblc main stack, but the runner
refuses the reserved `cblc` gate with `ExtensionsUnavailable` before invoking any
provider. Signed acceptance alone is insufficient to prove the complete private
extension relation. There is no feature that bypasses this guard. The leaf now
has real extension proof tests; facade activation still requires the verified
acceptance and atomic pin-transition integration. No successful
balance change permission can currently be minted by these adapters.

LegalGate delegates exact-action checks to clbs. It applies even when action
policy is empty and cannot be disabled by a rulebook switch. Legal errors fail
closed. Qualified authority verification remains a service/leaf responsibility.

The development gate exists only in cgbl. cgts exports no development module in
any build; CI verifies absence in a release profile with debug assertions enabled.

## Persistence

The service owns one crlt pool, credentials and migration history. `MemoryStore`
and `LibsqlStore` implement the same atomic claim/result contract. Install `SCHEMA`
and `legal_storage::SCHEMA` with service-assigned migration numbers. Legal metadata
persistence belongs to this host adapter; `clbs` has no database connection.

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

Crow runs formatting, strict Clippy, native and release tests, real
libSQL round trips, rollback/concurrency/restart checks, signed vouchers, signed
v2 profile fixtures, real BBS+ blind issuance and authenticated presentation,
legal vetoes and compile-fail capability boundaries. It also rejects floating or
duplicated corbet dependency revisions in Cargo.lock and cargo metadata. The
live Turso probes are ignored by default and require explicit authorization,
selection and disposable database credentials. No Cargo runs on the workstation.

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
Positive facade extension-spend/restart tests remain open until the verified
acceptance adapter is implemented; the current tests require refusal for all
contexts. Leaf proof success alone does not activate these adapters.

All retained provider expiries are rounded down to UTC days before constructing
CheckedGate or committing a claim. Evidence that cannot reach the next day cannot
be retained. Both store adapters and the SQL constraint reject precise retained
expiries. Transient profile checks keep second precision because they certify the
current signed profile at the verification instant and are never persisted.

## Payment handoff

`payments::PaymentGate` accepts only in-process `cpmt::payments::Evidence`.
The payment caller selects the required fact and lifetime before this boundary;
community rulebook switches and the legal veto still run normally. Receipt claims
share the `payment` domain across gate/provider identities so changing either
cannot redeem the same receipt again. Retained expiry uses the existing exclusive
UTC-day floor. Payment execution and commercial policy are not added to cgts.


For level-and-period access, `payments::PaidAccessGate` accepts the protected
`cpmt::access::PaidAccess` result. The payment library verifies the configured
financial terms and transforms them before this boundary. The gate checks the
exact requested level (no implicit ranking), current period and existing context
and provider binding. It receives no amount, currency, payment instrument or
provider response. `PaymentGate` remains available for other explicitly selected
financial facts. Production dispatch, cost authorization and local simulation
remain inside cpmt/crpt; these gate adapters never contact payment providers.


Time inputs in this host facade describe an explicit as-of evaluation. They are
bound into the checked policy context; they are not a live-clock implementation.
A successful result at that instant does not authorize a later action after its
validity ends. The hosting service owns the final authorization boundary: use its
trusted current clock, check result expiry and current policy/legal state, and
re-evaluate when the earlier context is no longer current. Passing an old `now`
through delayed storage work does not establish completion-time freshness.


The original account-service port installs one configured native Balance service
for this community. `account` first performs the existing legal/context preflight
and compares the independent Community-owned pseudonym with the exact subject;
it never creates a gate receipt. A single native worker owns the service and
its live clock and caller-owned atomic storage. The actual member/Policy lease
is moved into the queued command and retained through service completion even
if the asynchronous caller cancels. A panicked worker stays fenced; there is no
replacement ledger, copied state or automatic retry after an uncertain effect.
The host must perform the original current policy epoch/cohort/member/device
checks before forwarding. Publication and settlement are privileged host work,
not added member request variants. Tests preserve genuine signed Status and
SQL/lease/race behavior with the maintained native verifier. They require real
CBLC artifact/worker inputs and are authored, not executed or proof-qualified.


Privileged `account_host` commands share that exact worker and return the same
owned caller guard on success. PublishRecord runs the original epoch publication
and actual material projection consecutively, crosschecking descriptor identity;
VerifierMaterial bootstrap keeps an absent record epoch absent and cannot enable
G2. VerifiedCheckpoint, TuneWaiting and SettleBatch only delegate original native
owner methods. They have no serde decoder, member DTO or arbitrary callback/key.
The caller continues actual Policy/Beacon work under the returned guard; cancelled
calls retain it until native completion. A possibly committed native operation
followed by any later publication failure requires reconciliation, never a
replacement ledger or a claim of rollback. Root-board remains its separate
original CPSD/Policy owner, not an account-worker request.

Native hosts install `with_native_account_service` and retain `account_shutdown`
outside Community/Policy/member locks. The handle belongs to that exact service:
it fences new and queued work, cancels every real account/extension proof owner,
and joins the original worker after in-flight operations and service final drop.
Caller cancellation cannot abandon the join; concurrent/later waiters observe
the same actual completion. A possibly committed operation whose response is
fenced reports uncertainty, not known nonexecution. The generic constructor has
explicit drain-only semantics and does not pretend it can preempt a verifier.

Graceful host drain budgets are separate from mandatory cleanup. Hosts await this
join before tearing down the CRLT async runtime; operating-system process cleanup
has no hard real-time promise. `begin_shutdown` synchronously initiates the same
shared join attempt without blocking the reactor; it never reports completion.
This lets a startup guard initiate cleanup even when its factory future is
abandoned. Dropping the service owner also initiates this attempt. If starting
the join fails, the original worker remains available for a retained handle to
retry. The host retains that handle before any fallible post-construction await
and awaits `shutdown` on all setup/error paths before runtime teardown; initiation
or Drop is not a substitute for this mandatory lifetime contract.
Real SQL lease/cancelled-wait tests and an actual native proof followed by clone
cancellation are authored; execution remains dependent on the useful native route.

The typed `VerifyPinChange` command runs on that same configured native worker
and returns only CBLC's sealed completed-spend capability with the retained owner
lease. Receipt bytes use the original request/acceptance/update fields, bounded
before decoding and checked by the native owner. This is not current membership
authority. The legacy standalone synchronous decoder still refuses because it
has no configured native owner. CMBR must verify current key/lifecycle/legal
authority under the actual pin transaction before consuming the exact binding.

The configured Community account path uses `account_authorized`. Its original
single worker retains the actual owner callback and leases until the native
command finishes, including after caller cancellation. Balance invokes the
callback at its existing writer-held commit decision; the queue does not mint
member authority or replace proof verification. The generic lower-owner account
method remains available for compositions which do not claim Community authority.

The libSQL spent-marker owner can stage an original verified claim through
`claim_in_transaction` in a caller-owned admission transaction. It requires the
exact same database handle and community, opens no second writer, and never
commits. It consumes the transaction and returns ownership only on success;
refusal or cancellation therefore rolls back earlier staged lifecycle work.
The caller still verifies the leaf evidence and commits all admission/creation
state together. Staging a nullifier is neither membership nor a durable receipt.
