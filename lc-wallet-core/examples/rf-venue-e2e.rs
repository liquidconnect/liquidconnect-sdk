//! Live SDK-signed drill against the Rolling Future venue: two SDK
//! wallets log in by wallet-key challenge (the wallet key becomes the
//! account leaf key), trade against each other — a signed resting limit
//! and a signed immediate-or-cancel "market" — and one withdraws, every
//! engine transition wallet-key-signed. On the covenant-driven venue the
//! rf-driver sidecar broadcasts these exact signatures inside the on-chain
//! open/fill/withdraw transitions.
//!
//!     cargo run --example rf-venue-e2e -- <seedA-hex-32> <seedB-hex-32> [base-url]
//!
//! base-url defaults to https://paper.swaption.io. Seeds are master
//! blinding keys (the wallet identity is deterministic from them, like a
//! real wallet's).

use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::venue::{sign_login, sign_order, sign_withdraw, withdraw_digest, OrderSide};

struct Venue {
    base: String,
}

impl Venue {
    fn post(&self, path: &str, fields: &[(&str, &str)]) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{path}", self.base);
        let resp = ureq::post(&url)
            .timeout(std::time::Duration::from_secs(30))
            .send_form(fields);
        let body = match resp {
            Ok(r) => r.into_string()?,
            Err(ureq::Error::Status(code, r)) => {
                let b = r.into_string().unwrap_or_default();
                anyhow::bail!("{path} -> {code}: {b}");
            }
            Err(e) => anyhow::bail!("{path}: {e}"),
        };
        Ok(serde_json::from_str(&body)?)
    }

    fn state(&self, token: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}/api/state?token={token}", self.base);
        Ok(serde_json::from_str(&ureq::get(&url).call()?.into_string()?)?)
    }
}

/// Raw base units -> the decimal string the venue's form parser expects.
fn dec(raw: u64) -> String {
    format!("{}.{:08}", raw / 100_000_000, raw % 100_000_000)
}

fn login(v: &Venue, key: &WalletKey, label: &str) -> anyhow::Result<(String, u64)> {
    let ch = v.post("/api/sdk/challenge", &[])?;
    let challenge = ch["challenge"].as_str().expect("challenge").to_string();
    let (_digest, sig) = sign_login(key, &challenge);
    let pk_hex = hex::encode(key.public_key().serialize());
    let r = v.post(
        "/api/sdk/login",
        &[("pk", pk_hex.as_str()), ("challenge", &challenge), ("sig", &sig.to_string())],
    )?;
    if let Some(e) = r["error"].as_str() {
        anyhow::bail!("login {label}: {e}");
    }
    let token = r["token"].as_str().expect("token").to_string();
    let account = r["account"].as_u64().expect("account");
    println!("{label}: wallet {} -> account {account}", &pk_hex[..8]);
    Ok((token, account))
}

fn signed_order(
    v: &Venue,
    key: &WalletKey,
    token: &str,
    side: OrderSide,
    price_raw: u64,
    qty_raw: u64,
    ioc: bool,
) -> anyhow::Result<serde_json::Value> {
    let st = v.state(token)?;
    let session = st["session"].as_u64().expect("session") as u32;
    let nonce = st["me"]["nextNonce"].as_u64().expect("nextNonce");
    let expiry = session + 24;
    let (digest, sig) = sign_order(key, side, price_raw, qty_raw, expiry, nonce);
    let side_s = if matches!(side, OrderSide::Buy) { "buy" } else { "sell" };
    let (price_s, qty_s) = (dec(price_raw), dec(qty_raw));
    let (expiry_s, nonce_s, sig_s) = (expiry.to_string(), nonce.to_string(), sig.to_string());
    let mut fields = vec![
        ("token", token),
        ("side", side_s),
        ("price", price_s.as_str()),
        ("qty", qty_s.as_str()),
        ("expiry", expiry_s.as_str()),
        ("nonce", nonce_s.as_str()),
        ("sig", sig_s.as_str()),
    ];
    if ioc {
        fields.push(("ioc", "1"));
    }
    let r = v.post("/api/order", &fields)?;
    if let Some(e) = r["error"].as_str() {
        anyhow::bail!("order refused: {e}");
    }
    println!(
        "  {side_s} {} @ {} expiry {expiry} nonce {nonce}{}",
        qty_s,
        price_s,
        if ioc { " (ioc)" } else { "" }
    );
    println!("    digest {}", hex::encode(digest));
    println!("    sig    {sig}");
    Ok(r)
}

fn signed_withdraw(
    v: &Venue,
    key: &WalletKey,
    token: &str,
    amt_raw: u64,
) -> anyhow::Result<()> {
    let pk = key.public_key().serialize();
    let amt_s = dec(amt_raw);
    for attempt in 0..3 {
        let p = v.post("/api/withdraw/prepare", &[("token", token), ("amount", amt_s.as_str())])?;
        if let Some(e) = p["error"].as_str() {
            anyhow::bail!("withdraw prepare: {e}");
        }
        let root: [u8; 32] = hex::decode(p["root"].as_str().expect("root"))?
            .try_into()
            .expect("root len");
        let (digest, sig) = sign_withdraw(key, amt_raw, &root);
        // never sign blind: the digest must rebuild from the parts
        anyhow::ensure!(
            hex::encode(digest) == p["digest"].as_str().unwrap_or(""),
            "venue digest does not match a local rebuild"
        );
        debug_assert_eq!(
            digest,
            withdraw_digest(&pk, amt_raw, &lc_wallet_core::venue::p2tr_spk_hash(&pk), &root)
        );
        let sig_s = sig.to_string();
        let r = v.post(
            "/api/withdraw",
            &[("token", token), ("amount", amt_s.as_str()), ("sig", sig_s.as_str())],
        )?;
        match r["error"].as_str() {
            None => {
                println!("  withdraw {amt_s} ok");
                println!("    digest {}", hex::encode(digest));
                println!("    sig    {sig}");
                return Ok(());
            }
            Some(e) if e.contains("prepare and sign again") && attempt < 2 => {
                println!("  venue moved under the signature — re-preparing ({e})");
            }
            Some(e) => anyhow::bail!("withdraw refused: {e}"),
        }
    }
    anyhow::bail!("withdraw kept missing the moving root after 3 attempts")
}

fn seed32(hex_s: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(hex_s)?;
    b.try_into().map_err(|_| anyhow::anyhow!("seed must be 32 bytes of hex"))
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let seed_a = seed32(&args.next().expect("seedA hex is the first argument"))?;
    let seed_b = seed32(&args.next().expect("seedB hex is the second argument"))?;
    let base = args.next().unwrap_or_else(|| "https://paper.swaption.io".to_string());
    let v = Venue { base };

    let key_a = WalletKey::new(&seed_a, Network::LiquidTestnet);
    let key_b = WalletKey::new(&seed_b, Network::LiquidTestnet);
    let (tok_a, _) = login(&v, &key_a, "wallet A")?;
    let (tok_b, _) = login(&v, &key_b, "wallet B")?;

    // one price both sides agree on: the session open, rounded to the
    // venue's whole-unit tick
    let st = v.state(&tok_a)?;
    let open = st["sessionOpenRaw"].as_u64().expect("sessionOpenRaw");
    let tick = 100_000_000u64;
    let price = ((open + tick / 2) / tick * tick).max(tick);
    let qty = 1_000u64; // sats

    println!("A rests a signed sell:");
    let ra = signed_order(&v, &key_a, &tok_a, OrderSide::Sell, price, qty, false)?;
    anyhow::ensure!(!ra["restId"].is_null(), "A's limit should rest");
    println!("B lifts it with a signed IOC buy:");
    let rb = signed_order(&v, &key_b, &tok_b, OrderSide::Buy, price, qty, true)?;
    anyhow::ensure!(
        rb["iocCancelled"] == serde_json::json!(false),
        "B's ioc should fill completely, got {rb}"
    );
    let mb = v.state(&tok_b)?;
    anyhow::ensure!(
        mb["me"]["marginRaw"].as_u64().unwrap_or(0) > 0,
        "B should be margined after the fill"
    );

    println!("B withdraws, wallet-key-signed:");
    signed_withdraw(&v, &key_b, &tok_b, qty)?;

    println!("\nSDK-signed drill complete: login, resting limit, IOC fill and");
    println!("withdrawal all signed by the wallet keys themselves.");
    Ok(())
}
