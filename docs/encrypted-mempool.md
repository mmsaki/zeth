# Encrypting the mempool — feedback on EIP-8105 (EEM) and EIP-8184 (LUCID)

Feedback on the two draft mempool-encryption EIPs, reviewed from two angles — an
execution client ([zeth](https://github.com/mmsaki/zeth)) and an intent / limit-order
DEX ([AsyncSwap](https://asyncswap.org)) — and backed by runnable demos against zeth's
own RPC.

- `examples/zeth-sandwich/` — an end-to-end sandwich through zeth's mempool + builder:
  real signed txs, a real pending pool, a searcher that listens and bundles
  `[front, victim, back]`. A private bundle (the outcome every encrypted-mempool design
  targets) neutralizes it. This is the empirical backbone — it shows mempool *visibility*
  is the whole game, and what changes when you remove it.
- `examples/eip8105_encrypted_mempool.zig` — the EIP-8105 `0x05`→reveal→`0x06` envelope
  flow on zeth's RLP codec, including the key-withholding "paid DoS".
- `examples/eip8184_lucid.zig` — the EIP-8184 (LUCID) sealed-tx flow: ChaCha20-Poly1305
  encryption + commit-before-reveal, and the ToB-fee accounting that shows the withholding
  penalty landing on the *sender*, not the publisher (§ the decisive gap).

```sh
cd examples/zeth-sandwich && ./demo.sh     # sandwich, then the private-mempool fix
zig build enc-demo                          # EIP-8105 envelope + withholding
zig build lucid-demo                        # EIP-8184 sealed tx + ToB-fee withholding
```

```
Part 1 — plaintext mempool      user 54.9 token1 (sandwiched), attacker MEV 41.9
Part 2 — encrypted mempool      user 90.9 token1 (fair — searcher saw nothing to wrap)
```

![sandwich demo: the orderflow trace from `zeth node -v`](../examples/zeth-sandwich/demo-logs.png)

## The two designs, in one paragraph

**EIP-8105 (EEM)** is *social*: two new `0x05`/`0x06` tx types, an on-chain key-provider
registry, and a trust graph that constrains sequencing; withholding is deterred by
off-chain reputation. **EIP-8184 (LUCID)** is *cryptographic + economic*: sealed
transactions (`ST_TICKET` + `ST` 2718 types) commit in the beacon block before reveal,
keys are released by a designated *key publisher* after the schedule is fixed, and the
PTC votes on key *timeliness*; withholding is priced through a top-of-block (ToB) fee
(`TOB_FEE_FRACTION = 128`). LUCID is the stronger base — it prices what 8105 only shames
— but the two share the decisive gap below.

## First, the uncomfortable question: is enshrinement worth it?

The encrypted-mempool *outcome* already exists in production, off-chain: private RPCs,
Flashbots Protect / MEV-Share, and TEE-builder networks (BuilderNet) give users an
unsniped path to inclusion today. The sandwich demo proves it on an **unmodified L1** — a
private bundle gets the victim a fair fill right now, no fork required. So the burden is on
enshrinement to beat that status quo on the three things off-chain orderflow *cannot*
credibly provide:

1. **Credible neutrality** — anyone can submit, no allowlist, no relay to trust.
2. **Censorship resistance** — inclusion guaranteed by consensus, not a relay's goodwill.
3. **No new trusted third party** — today you trade a public-mempool adversary for a
   trusted relay/builder; enshrinement is only worth it if it removes that trust, not
   relocates it.

Judged against that bar, **both drafts currently relocate trust rather than remove it**
(§ withholding), and **both leave MEV private rather than neutral** (§ backrunning). Until
those two are closed, an enshrined encrypted mempool is strictly more complex than the
private orderflow we already run, without delivering the neutrality that would justify the
consensus surface. The recommendations below are what would tip that balance.

## The decisive gap: withholding accountability lands on the wrong party

Both EIPs leave the *key holder* with no in-protocol cost for withholding.

- **8105**: the envelope fee is charged at inclusion even when the provider never reveals
  (`withhold = true` → no `0x06`). The tx is paid for and never runs — a *paid DoS*. Only
  reputation deters it, and a provider with exclusive orderflow has little reason to
  protect its reputation. `keyId(signer)` namespacing stops id-reuse frontrunning (cheap,
  keep it) but does nothing about a provider that simply declines.
- **8184**: the non-reveal penalty is the **sender's** forfeited ToB fee (reveal refunds
  `tob_fee · 127/128`; non-reveal forfeits the full `tob_fee`), *not* the key publisher's.
  Publisher liability is explicitly out-of-protocol — a voluntary "sponsor" ST where the
  publisher sets `max_tob_fee = n·d·TOB_FEE_FRACTION` to absorb the penalty. A user picks a
  publisher; if that publisher withholds, **the user pays and the withholder loses nothing
  in protocol.** LUCID prices *user-side* probabilistic frontrunning well, but the actual
  adversary in the withholding threat — an exclusive publisher — is untouched. This is
  8105's trust gap, relocated from reputation to the victim's wallet.

**Improvement (applies to both, and LUCID already has the primitive).** LUCID defines
`LucidKeyTimelinessVote` — a PTC bitfield attesting which keys arrived on time, with a
"missing" threshold `2·timely_1 ≤ timely_1 + timely_0 + late_0 + equivocated`. That is
liveness *detection*; it stops one step short of *accountability*. Bind a **publisher
bond, slashable when the PTC attests an unjustified non-reveal.** It turns the vote LUCID
already collects into the consequence both designs lack, keeps the crypto swappable, and
is the single change that most moves enshrinement past "relocates trust."

## Use FRAME (8141) as the substrate, not an option

8105 runs a parallel `0x05`/`0x06` lifecycle; LUCID adds `ST_TICKET`/`ST` types and
mentions FRAME only as an optional reserved frame. Both re-derive validation / payment /
execution that FRAME already decomposes, with a mempool validation prefix. Map encryption
*onto* FRAME instead of alongside it: the ST ticket (or 8105 envelope) is a
validation+payment frame; the ciphertext is the execution frame. One frame loop, one
gas-accounting path, and the cipher and signature scheme become pluggable verifiers
(post-quantum sigs, decryption-key checks) — no second tx-type lifecycle to keep in
consensus. This is the cheapest future-proofing available to either EIP.

## Execution quality: the encrypted lane is a premium good

LUCID gives sealed txs only `tob_gas_limit = block.gas_limit / 8`
(`TOB_GAS_FRACTION_DENOMINATOR = 8`). Under load the encrypted lane congests while 7/8 of
the block stays public, so encryption becomes a *premium* — and `max_preceding_commitments
= 0` (absolute top-of-block) is settled by a ToB-fee auction. Protection that is auctioned
re-centralizes on whoever can pay: MEV by another name, one layer up. Two further costs:

- **`dual_gas_used = max(len(ciphertext_envelope), len(plaintext.data)) + execution_gas`**
  charges for ciphertext size — a structural tax on privacy, paid by every sealed tx.
- **Priority fee is not reconciled** (blockspace is consumed at commitment), so a sealed
  tx cheap to execute still pays as if it filled its `gas_limit` — widening the price gap
  between the encrypted and plaintext lanes.

Right-sizing `TOB_GAS_FRACTION_DENOMINATOR`, and publishing the **on-chain decryption gas
cost** (LUCID decrypts ChaCha20-Poly1305 on-chain; 8105 says "decryption cost subtracted
from allowance" / "hardcoded small gas limit per key" with no numbers) is a prerequisite
for review — two clients picking different constants is a consensus split.

## Monetize benign backrunning, or it routes private anyway

A benign backrun — e.g. an AsyncSwap filler settling a maker's order once the pool reaches
its limit price — is value-adding, not predatory. Neither EIP gives it a home. LUCID
reveals and executes a sealed tx in the *next* block's ToB; by reveal time the schedule is
fixed, so a fill that must reference the just-revealed order cannot be placed in a neutral,
monetizable lane — it routes through a private relationship instead, recreating exclusive
orderflow. The fix is symmetric to the withholding fix: a **reveal-time, provider-neutral
Rest-of-Block lane** for txs that reference an already-revealed sealed tx. LUCID's existing
ToB/RoB split is the natural place to host it; encrypting the public mempool without it
moves MEV private rather than removing it.

## Application impact (AsyncSwap, an intent/limit-order DEX)

Under either design a maker's intent is hidden until inclusion — no sniping, which is the
win. But fillers can then no longer see fillable orders, so fill timing collapses onto the
reveal order: in 8105 the *preceding-provider advantage* the spec names and does not
mitigate; in LUCID the `max_preceding_commitments` / ToB-fee auction. For an order-fill
market that timing *is* the product, not "a single bit". `max_preceding_commitments` is
actually a useful primitive here — a filler wanting to land immediately after a specific
order can express it — but only if the backrun lane above keeps it neutral; otherwise fills
re-centralize onto whoever wins the ToB auction.

## Adoption & deployment

LUCID is the larger consensus surface: it couples to FOCIL inclusion lists, PTC key-
timeliness votes, beacon-block ST-commitments, recovery payloads (which "cannot commit to
new STs"), and on-chain AEAD decryption — it lands only after FOCIL/PTC do. 8105's gas
constants are "TBD". Both accelerate by (1) publishing exact gas constants first, and
(2) validating incentives **off-chain** before enshrining — the private-orderflow path the
demo exercises — then enshrining once withholding-accountability and the backrun lane are
proven, i.e. once enshrinement actually clears the §"is it worth it?" bar.

## Recommendations

1. Enshrine **key-holder accountability**: a bond slashable on LUCID's PTC key-timeliness
   attestation. Don't let the withholding penalty fall on the victim — this is the change
   that justifies enshrinement over private orderflow.
2. Make **FRAME (8141) the substrate**, not an option — one lifecycle, swappable crypto.
3. Define a **neutral, reveal-time backrun/fill lane** so benign backrunning stays public.
4. Publish **exact gas constants** for decryption, key validation, and the ToB lane size.
5. Prove the economics with **off-chain encrypted orderflow first**; enshrine second.
