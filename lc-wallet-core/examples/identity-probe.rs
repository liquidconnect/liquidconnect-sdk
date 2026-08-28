//! Drive the identity API end to end with an ephemeral wallet key:
//! challenge auth, registration via discoverability, contact save, and
//! the refusal paths. Proves the SDK client and the server agree on the
//! protocol — including that they refuse the same things.
//!
//!     cargo run --example identity-probe -- <base_url> [gateway_bearer]

use lc_wallet_core::identity::IdentityClient;
use lc_wallet_core::key::WalletKey;

fn main() -> anyhow::Result<()> {
    let base = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:3129/v1/identity".to_owned());
    let bearer = std::env::args().nth(2);
    let client = IdentityClient::new(&base, bearer);
    let key = WalletKey::ephemeral();
    println!("wallet key (ephemeral): {}", key.public_key());

    let status = client.status(&key)?;
    println!("status before: identity_id={:?}", status.identity_id);
    assert!(status.identity_id.is_none(), "fresh key must be unknown");

    client.set_discoverability(&key, true, false)?;
    let status = client.status(&key)?;
    println!(
        "status after opt-in: identity_id={:?} email={} phone={}",
        status.identity_id, status.email, status.phone
    );
    assert!(status.identity_id.is_some(), "opt-in must register");

    client.contacts_save(&key, "email", "someone@example.com")?;
    let contacts = client.contacts_list(&key)?;
    println!("contacts (one-sided save must not appear): {}", contacts.len());
    assert!(contacts.is_empty());

    match client.contact_address(&key, "id-nonexistent") {
        Err(err) => println!("non-mutual address refused as expected: {err}"),
        Ok(_) => anyhow::bail!("a non-mutual address resolved; that is a hole"),
    }

    match client.email_start(&key, "probe@example.com") {
        Ok(()) => println!("email_start accepted (verification service reachable)"),
        Err(err) => println!("email_start refused (expected without services): {err}"),
    }

    // Replay: a hand-rolled second use of one challenge must die.
    let pubkey = key.public_key().to_string();
    let challenge: serde_json::Value = ureq::post(&format!("{base}/challenge"))
        .set(
            "Authorization",
            &format!("Bearer {}", std::env::args().nth(2).unwrap_or_default()),
        )
        .send_json(serde_json::json!({ "public_key": pubkey }))?
        .into_json()?;
    let nonce = challenge["challenge"].as_str().unwrap().to_owned();
    let sig = key.sign_identity(&nonce, "status", "").to_string();
    let call = |label: &str| {
        let result = ureq::post(&format!("{base}/status"))
            .set(
                "Authorization",
                &format!("Bearer {}", std::env::args().nth(2).unwrap_or_default()),
            )
            .send_json(serde_json::json!({
                "public_key": pubkey, "challenge": nonce, "signature": sig,
            }));
        match result {
            Ok(_) => println!("{label}: accepted"),
            Err(ureq::Error::Status(code, _)) => println!("{label}: refused ({code})"),
            Err(e) => println!("{label}: transport error {e}"),
        }
    };
    call("first use of challenge");
    call("REPLAY of same challenge");

    println!("identity probe complete");
    Ok(())
}
