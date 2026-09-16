//! Simplified onion-construction demo for a 4-node Lightning route:
//! Alice -> Carol -> Erin -> Dave.
//!
//! What is real: AES-256-GCM authenticated encryption (RustCrypto `aes-gcm`),
//! and the route data (amounts, channel IDs, payment hash) copied from a real
//! `lncli queryroutes` / `lncli decodepayreq` run on a Polar regtest network.
//!
//! What is simplified (NOT BOLT 4 Sphinx):
//! - Per-hop keys are random here; real Sphinx derives them via ECDH with a
//!   fresh ephemeral key per payment.
//! - No fixed-size (1300-byte) packet padding, so layer size leaks route length.
//! - No HMAC chain for per-hop integrity checks.
//! - Payloads are JSON; real payloads are TLV-encoded.
//!
//! Only the peeling property is shown: each hop decrypts exactly one layer.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ForwardingHopLayer {
    role: String,
    next_hop_chan_id: String,
    amount_to_forward_msat: u64,
    encrypted_payload_for_next_hop: String,
}

#[derive(Serialize, Deserialize)]
struct FinalHopLayer {
    role: String,
    amount_to_forward_msat: u64,
    payment_hash: String,
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypts with AES-256-GCM. Output is base64(nonce || ciphertext || tag).
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("encryption failed");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    STANDARD.encode(out)
}

/// Decrypts a blob produced by `encrypt`. Fails if the key is wrong or the
/// blob was modified, since GCM authenticates the ciphertext.
fn decrypt(key: &[u8; 32], blob: &str) -> Result<Vec<u8>, String> {
    let raw = STANDARD.decode(blob).map_err(|e| e.to_string())?;
    if raw.len() < 12 {
        return Err("blob too short".into());
    }
    let (nonce, ciphertext) = raw.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "decryption failed: wrong key or tampered blob".into())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n {
        format!("{}...(truncated)", &s[..n])
    } else {
        s.to_string()
    }
}

fn print_forwarding_layer(layer: &ForwardingHopLayer) {
    let shown = ForwardingHopLayer {
        role: layer.role.clone(),
        next_hop_chan_id: layer.next_hop_chan_id.clone(),
        amount_to_forward_msat: layer.amount_to_forward_msat,
        encrypted_payload_for_next_hop: truncate(&layer.encrypted_payload_for_next_hop, 44),
    };
    println!("{}", serde_json::to_string_pretty(&shown).unwrap());
}

fn main() {
    // One symmetric key per hop. In real Sphinx each is an ECDH shared secret
    // between Alice's ephemeral key and that hop's node key.
    let carol_key = random_key();
    let erin_key = random_key();
    let dave_key = random_key();


    const PAYMENT_HASH: &str = "a0d05d169472b7dcb5729846926161115ff387149f57d7198b8de03c1ee75f83";

    // ---- Alice builds the onion from the inside out ----

    let dave_layer = FinalHopLayer {
        role: "final_hop".into(),
        amount_to_forward_msat: 100_000_000,
        payment_hash: PAYMENT_HASH.into(),
    };
    let encrypted_for_dave = encrypt(&dave_key, serde_json::to_string(&dave_layer).unwrap().as_bytes());

    let erin_layer = ForwardingHopLayer {
        role: "forwarding_hop".into(),
        next_hop_chan_id: "236395000037377".into(), 
        amount_to_forward_msat: 100_000_000, // forwards this amount and keeps 1100 msats(1 sats)       
        encrypted_payload_for_next_hop: encrypted_for_dave,
    };
    let encrypted_for_erin = encrypt(&erin_key, serde_json::to_string(&erin_layer).unwrap().as_bytes());

    let carol_layer = ForwardingHopLayer {
        role: "forwarding_hop".into(),
        next_hop_chan_id: "236395000102913".into(), 
        amount_to_forward_msat: 100_001_100,        // forwards this amount and keeps 1100 msats(1 sats)   
        encrypted_payload_for_next_hop: encrypted_for_erin,
    };
    let encrypted_for_carol = encrypt(&carol_key, serde_json::to_string(&carol_layer).unwrap().as_bytes());

    println!("=== What Alice sends to Carol ===");
    println!("{}\n", truncate(&encrypted_for_carol, 80));

    // ---- Each hop peels exactly one layer ----

    let carol_view: ForwardingHopLayer =
        serde_json::from_slice(&decrypt(&carol_key, &encrypted_for_carol).unwrap()).unwrap();
    println!("=== What Carol learns after decrypting her layer ===");
    print_forwarding_layer(&carol_view);
    println!(
        "\n>> Carol forwards {} msat on channel {} (to Erin).\n\
         >> She cannot tell whether Erin is the final recipient,\n\
         >> and she cannot read the blob meant for the next hop.",
        carol_view.amount_to_forward_msat, carol_view.next_hop_chan_id
    );
    match decrypt(&carol_key, &carol_view.encrypted_payload_for_next_hop) {
        Ok(_) => println!(">> (unexpected) Carol opened the inner layer"),
        Err(e) => println!(">> Carol trying her own key on the inner blob: {e}\n"),
    }

    let erin_view: ForwardingHopLayer =
        serde_json::from_slice(&decrypt(&erin_key, &carol_view.encrypted_payload_for_next_hop).unwrap()).unwrap();
    println!("=== What Erin learns after decrypting her layer ===");
    print_forwarding_layer(&erin_view);
    println!(
        "\n>> Erin received {} msat from Carol and forwards {} msat,\n\
         >> keeping {} msat as her fee. Nothing in her layer names\n\
         >> Carol or Alice, and she can't tell whether Dave is final.\n",
        carol_view.amount_to_forward_msat,
        erin_view.amount_to_forward_msat,
        carol_view.amount_to_forward_msat - erin_view.amount_to_forward_msat
    );

    let dave_view: FinalHopLayer =
        serde_json::from_slice(&decrypt(&dave_key, &erin_view.encrypted_payload_for_next_hop).unwrap()).unwrap();
    println!("=== What Dave learns after decrypting the final layer ===");
    println!("{}", serde_json::to_string_pretty(&dave_view).unwrap());
    println!(
        "\n>> Dave sees he is the final hop and checks the amount and\n\
         >> payment hash against his own invoice. Nothing in this\n\
         >> packet identifies Alice, Carol, or Erin."
    );
}
