# lightning-multi-hop-demo

Runnable code examples for a technical article series on how multi-hop payments work in the Lightning Network.

The route data in these demos (channel IDs, amounts, fees and the payment hash) comes from a real 4-node LND regtest network built with [Polar](https://lightningpolar.com/). The payment path is:

```
Alice ──> Carol ──> Erin ──> Dave
 sender   forwarder  forwarder  recipient
```

> **These are teaching simulations, not protocol implementations.** They show *concepts* using real numbers. Do not use this code to build, send or parse real Lightning packets.

## Article series

| Part | Topic | Demo |
|---|---|---|
| 1 | Understanding Lightning's Multi-Hop Payments: A Technical Deep Dive | [`onion-construction/`](./onion-construction) |
| 2 | How Lightning Picks a Route | coming soon |
| 3 | What Happens When a Lightning Payment Fails | coming soon |

## Demos

### `onion-construction/`

Shows the **peeling property** of onion routing. Alice encrypts payment instructions in nested layers, one per hop. Each hop decrypts only its own layer, learns only where to forward next and how much, and passes on an encrypted blob it cannot read.

**What is real**

- AES-256-GCM authenticated encryption from the RustCrypto [`aes-gcm`](https://crates.io/crates/aes-gcm) crate
- Amounts, channel IDs and fees from `lncli queryroutes`
- The payment hash from `lncli addinvoice` / `lncli decodepayreq`

**What is simplified compared with BOLT 4 Sphinx**

| Real Sphinx | This demo |
|---|---|
| Per-hop keys derived via ECDH with a fresh ephemeral key per payment | Random per-hop keys |
| Packet padded to a fixed 1,300 bytes, so route length is hidden | No padding |
| HMAC chain lets each hop detect tampering | Not included (GCM still authenticates each layer) |
| TLV-encoded hop payloads | JSON payloads |

**Route data used**

| Hop | Channel | Receives (msat) | Forwards (msat) | Fee (msat) |
|---|---|---|---|---|
| Carol | `236395000102913` (to Erin) | 100,002,200 | 100,001,100 | 1,100 |
| Erin | `236395000037377` (to Dave) | 100,001,100 | 100,000,000 | 1,100 |
| Dave | final hop | 100,000,000 | n/a | 0 |

#### Run it

Requires a Rust toolchain ([rustup.rs](https://rustup.rs)). Tested with rustc 1.93.0.

```bash
cd onion-construction
cargo run
```

#### Sample output (shortened)

```
=== What Carol learns after decrypting her layer ===
{
  "role": "forwarding_hop",
  "next_hop_chan_id": "236395000102913",
  "amount_to_forward_msat": 100001100,
  "encrypted_payload_for_next_hop": "N7XnErjbn1pcVnXzNfgp...(truncated)"
}
>> Carol trying her own key on the inner blob: decryption failed: wrong key or tampered blob

=== What Erin learns after decrypting her layer ===
{
  "role": "forwarding_hop",
  "next_hop_chan_id": "236395000037377",
  "amount_to_forward_msat": 100000000,
  "encrypted_payload_for_next_hop": "031L4xdOtbBLD8ELwLfa...(truncated)"
}

=== What Dave learns after decrypting the final layer ===
{
  "role": "final_hop",
  "amount_to_forward_msat": 100000000,
  "payment_hash": "a0d05d169472b7dcb5729846926161115ff387149f57d7198b8de03c1ee75f83"
}
```

The encrypted strings differ on every run because keys and nonces are random.

## References

- [BOLT #4: Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [BOLT #11: Invoice Protocol for Lightning Payments](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [lightningnetwork/lightning-onion](https://github.com/lightningnetwork/lightning-onion), the Go Sphinx implementation used by LND
- [Polar](https://lightningpolar.com/), one-click Lightning regtest networks
