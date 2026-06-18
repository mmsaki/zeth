# Encrypted mempool (EIP-8105 / 8141) — feedback

Feedback on the draft mempool-encryption EIPs (8105 / 8141), with a runnable
prototype of the EIP-8105 `0x05`→reveal→`0x06` flow on zeth's RLP codec. Reviewed
against an execution client ([zeth](https://github.com/mmsaki/zeth)) and an
intent/limit-order DEX ([AsyncSwap](https://asyncswap.org)).

- `docs/encrypted-mempool-feedback.md` — this writeup
- `examples/encrypted-mempool-foundry/` — sandwich demo: MEV extracted in the clear vs neutralized under encryption
- `examples/eip8105_encrypted_mempool.zig` — the `0x05`→reveal→`0x06` envelope flow on zeth's codec

## Run

Sandwich (why it matters) — real swaps; stage 1 unencrypted mempool, stage 2 encrypted:

```sh
cd examples/encrypted-mempool-foundry && forge test -vv
```

```
fair out (no attacker)       90.9
victim out (unencrypted mp)  54.9   <- sandwiched, ~40% worse
attacker MEV profit          41.9
victim out (encrypted mp)    90.9   <- fair, nothing to sandwich
```

EL codec — the envelope flow on zeth's RLP codec + the key-withholding DoS:

```sh
zig build enc-demo
```

```
EIP-8105 encrypted-mempool flow (zeth RLP codec)
  reveal+decrypt -> 0x06 body 83B, matches source: true
  key withheld    -> decrypted: none  (envelope fee already charged → paid DoS)
```

## Test

```sh
zig build test                                       # zig demo + suite
cd examples/encrypted-mempool-foundry && forge test  # sandwich
```

## Position

- The unsolved part is the trust model, not the cipher. Every hard case (key
  withholding, preceding-provider reveal advantage, reorg-time reveals) is pushed
  to off-chain incentives. With no in-protocol consequence, orderflow re-centralizes
  onto whichever providers bootstrap reputation first.
- Use FRAME (8141) as the substrate instead of two bespoke tx types. The fee
  commitment is a validation frame; the encrypted blob is the execution frame.
  Reuses the frame loop, gas accounting, and mempool policy — no parallel
  `0x05`/`0x06` path.
- Encrypting the public mempool without a neutral, monetizable backrun channel
  moves MEV private rather than removing it.

## Application impact

An AsyncSwap fill is a benign backrun: the filler settles a maker's order after the
pool reaches its limit price. Under 8105 the maker's intent is hidden until inclusion
(no sniping — good), but fillers can no longer see fillable orders, so fill timing
collapses onto the key provider's reveal order. That is the preceding-provider
advantage the spec names and does not mitigate; for an order-fill market it is the
whole game, not "a single bit". Result: fills route private, recreating exclusive
orderflow.

Treat benign backrunning as first-class: a reveal-time, provider-neutral inclusion
lane for fills that reference an already-included order.

## EL: two tx types vs FRAME

8105 adds two EIP-2718 types and a second full lifecycle — envelope codec, a
key-provider registry contract (source "TBD"), CL replication, PTC key-validation,
a new attestation bitfield, and a cross-block `0x06`↔`0x05` correspondence check.

- Gas accounting is unspecified ("decryption cost subtracted from allowance",
  "hardcoded small gas limit per key" — no numbers). Two clients picking different
  values is a consensus split. Needs exact constants before it is review-complete.
- `0x06` adds a second signature path "for simplicity"; it is not simpler for the
  EL. Using the envelope signer as the sender removes a verification path and the
  unresolved envelope/payload cyclic reference.

FRAME already decomposes a tx into validation/payment/execution with a mempool
validation prefix. Map encryption onto it instead of alongside it, and the crypto
stays swappable (post-quantum sigs, decryption-key checks are just verifiers).

## Key withholding

The demo shows both halves:

- The attack is paid-for. A withholding provider keeps the envelope fee charged at
  inclusion while the tx never runs (`withhold = true` → no `0x06`). Off-chain
  reputation is the only deterrent, and a provider with exclusive orderflow has
  little reason to protect it.
- Key-id namespacing (`keyId(signer)`) stops id-reuse frontrunning — cheap, keep it
  — but does nothing about a provider that simply declines, or reveals selectively.
- The trust graph makes block building a reachability problem and concentrates flow
  on well-connected providers.

Ship in-protocol accountability (a provider bond, slashable on a PTC-attested
unjustified withhold), not reputation. Off-chain incentives at L1 scale is a
deferral, not a mitigation.

## Recommendations

- Rebase the encrypted-mempool design onto FRAME (8141), not `0x05`/`0x06`.
- Make provider accountability in-protocol (bonded, PTC-attested).
- Define a neutral, monetizable backrun/fill channel so intent fills stay public.
- Publish exact gas constants for decryption and key validation.
