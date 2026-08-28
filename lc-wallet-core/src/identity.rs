//! Client for the Liquid Connect identity API: give the wallet's user a
//! reachable identity — verified email (free), verified phone (0.5 USDT,
//! paid from the connected wallet itself) — plus contact discovery and
//! pay-to-contact.
//!
//! Every operation authenticates as the wallet key: fetch a single-use
//! challenge, sign it together with the action and its primary value
//! ([`crate::key::WalletKey::sign_identity`]), send the signature with
//! the request. No account, no password, no API key for the wallet —
//! control of the key is the identity, exactly as on the Connect wire.
//!
//! The phone flow in order: [`IdentityClient::phone_start`] opens an
//! order and quotes the fee (and, when the wallet has no session with
//! the identity service yet, returns a `liquidconnect://` link to
//! approve one — feed it to the wallet exactly like a scanned QR).
//! [`IdentityClient::phone_pay`] asks the service to put the fee payment
//! on the wallet as an ordinary sign request; the user approves it on
//! their own device. Poll [`IdentityClient::phone_status`] until
//! `paid`, then [`IdentityClient::phone_sms`] sends the code and
//! [`IdentityClient::phone_confirm`] records the anchor. Nothing in this
//! module handles money: the payment is a sign request like any other,
//! rendered and approved in the wallet.

use serde::Deserialize;

use crate::key::WalletKey;

pub struct IdentityClient {
    /// Base of the identity surface, ending at the route prefix: for a
    /// direct connection `http://127.0.0.1:3129/v1/identity`, through
    /// the public gateway `https://test.liquidconnect.io/api/identity`.
    base_url: String,
    /// The public gateway's bearer, when the deployment fronts the API
    /// with one. The wallet-key signature inside the request is the
    /// caller's real authentication either way.
    gateway_bearer: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityStatus {
    pub identity_id: Option<String>,
    #[serde(default)]
    pub email: bool,
    #[serde(default)]
    pub phone: bool,
    #[serde(default)]
    pub handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOutcome {
    pub verified: bool,
    #[serde(default)]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub txid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectHint {
    pub request_id: String,
    pub link: String,
}

#[derive(Debug, Deserialize)]
pub struct PhoneQuote {
    pub order_id: String,
    pub price_sats: u64,
    pub asset_id: String,
    pub connected: bool,
    /// Present when the wallet must approve a connection first; open it
    /// like a scanned QR payload.
    pub connect: Option<ConnectHint>,
}

#[derive(Debug, Deserialize)]
pub struct PhoneStage {
    /// awaiting_payment | awaiting_approval | paid | sms_sent | done
    pub stage: String,
    #[serde(default)]
    pub txid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContactMatch {
    pub input_index: usize,
    pub identity_id: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverOutcome {
    pub matched: Vec<ContactMatch>,
    #[serde(default)]
    pub unparsed_input_indexes: Vec<usize>,
}

#[derive(Debug, Deserialize)]
pub struct Contact {
    pub identity_id: String,
    #[serde(default)]
    pub handle: Option<String>,
}

impl IdentityClient {
    pub fn new(base_url: impl Into<String>, gateway_bearer: Option<String>) -> Self {
        IdentityClient {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            gateway_bearer,
        }
    }

    fn post(&self, path: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let mut request = ureq::post(&format!("{}{path}", self.base_url))
            .timeout(std::time::Duration::from_secs(30));
        if let Some(bearer) = &self.gateway_bearer {
            request = request.set("Authorization", &format!("Bearer {bearer}"));
        }
        match request.send_json(body) {
            Ok(response) => Ok(response.into_json()?),
            Err(ureq::Error::Status(code, response)) => {
                let detail = response
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
                    .unwrap_or_else(|| "no detail".to_owned());
                anyhow::bail!("identity API refused ({code}): {detail}")
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Fetch a challenge and sign one operation. Challenges are
    /// single-use, so this happens per call — cheap, and it keeps every
    /// request independently replayable-nowhere.
    fn authed(
        &self,
        key: &WalletKey,
        action: &str,
        value: &str,
        mut body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let pubkey = key.public_key().to_string();
        let challenge = self
            .post("/challenge", serde_json::json!({ "public_key": pubkey }))?
            .get("challenge")
            .and_then(|c| c.as_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("no challenge in reply"))?;
        let signature = key.sign_identity(&challenge, action, value);
        let object = body
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("body must be an object"))?;
        object.insert("public_key".to_owned(), pubkey.into());
        object.insert("challenge".to_owned(), challenge.into());
        object.insert("signature".to_owned(), signature.to_string().into());
        let path = format!("/{}", action_path(action));
        self.post(&path, body)
    }

    pub fn status(&self, key: &WalletKey) -> anyhow::Result<IdentityStatus> {
        let value = self.authed(key, "status", "", serde_json::json!({}))?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn email_start(&self, key: &WalletKey, email: &str) -> anyhow::Result<()> {
        self.authed(
            key,
            "email_start",
            email,
            serde_json::json!({ "email": email }),
        )?;
        Ok(())
    }

    pub fn email_confirm(
        &self,
        key: &WalletKey,
        email: &str,
        code: &str,
    ) -> anyhow::Result<VerifyOutcome> {
        let value = self.authed(
            key,
            "email_confirm",
            email,
            serde_json::json!({ "email": email, "code": code }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn phone_start(&self, key: &WalletKey, phone: &str) -> anyhow::Result<PhoneQuote> {
        let value = self.authed(
            key,
            "phone_start",
            phone,
            serde_json::json!({ "phone": phone }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn phone_pay(&self, key: &WalletKey, order_id: &str) -> anyhow::Result<()> {
        self.authed(
            key,
            "phone_pay",
            order_id,
            serde_json::json!({ "order_id": order_id }),
        )?;
        Ok(())
    }

    pub fn phone_status(&self, key: &WalletKey, order_id: &str) -> anyhow::Result<PhoneStage> {
        let value = self.authed(
            key,
            "phone_status",
            order_id,
            serde_json::json!({ "order_id": order_id }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn phone_sms(&self, key: &WalletKey, order_id: &str) -> anyhow::Result<()> {
        self.authed(
            key,
            "phone_sms",
            order_id,
            serde_json::json!({ "order_id": order_id }),
        )?;
        Ok(())
    }

    pub fn phone_confirm(
        &self,
        key: &WalletKey,
        order_id: &str,
        code: &str,
    ) -> anyhow::Result<VerifyOutcome> {
        let value = self.authed(
            key,
            "phone_confirm",
            order_id,
            serde_json::json!({ "order_id": order_id, "code": code }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn set_discoverability(
        &self,
        key: &WalletKey,
        by_contact_hash: bool,
        by_handle: bool,
    ) -> anyhow::Result<()> {
        let value = format!("{by_contact_hash}:{by_handle}");
        self.authed(
            key,
            "discoverability",
            &value,
            serde_json::json!({
                "by_contact_hash": by_contact_hash,
                "by_handle": by_handle,
            }),
        )?;
        Ok(())
    }

    pub fn contacts_discover(
        &self,
        key: &WalletKey,
        contacts: &[(String, String)],
    ) -> anyhow::Result<DiscoverOutcome> {
        let entries: Vec<serde_json::Value> = contacts
            .iter()
            .map(|(channel, value)| serde_json::json!({ "channel": channel, "value": value }))
            .collect();
        let value = self.authed(
            key,
            "contacts_discover",
            "",
            serde_json::json!({ "contacts": entries }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn contacts_save(
        &self,
        key: &WalletKey,
        channel: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        self.authed(
            key,
            "contacts_save",
            value,
            serde_json::json!({ "channel": channel, "value": value }),
        )?;
        Ok(())
    }

    pub fn contacts_list(&self, key: &WalletKey) -> anyhow::Result<Vec<Contact>> {
        let value = self.authed(key, "contacts_list", "", serde_json::json!({}))?;
        #[derive(Deserialize)]
        struct Reply {
            contacts: Vec<Contact>,
        }
        let reply: Reply = serde_json::from_value(value)?;
        Ok(reply.contacts)
    }

    pub fn contact_address(&self, key: &WalletKey, identity_id: &str) -> anyhow::Result<String> {
        let value = self.authed(
            key,
            "contact_address",
            identity_id,
            serde_json::json!({ "identity_id": identity_id }),
        )?;
        value
            .get("address")
            .and_then(|a| a.as_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("no address in reply"))
    }
}

/// The route each action lives at. Kept in one place so the signature's
/// action string and the URL cannot drift apart.
fn action_path(action: &str) -> &'static str {
    match action {
        "status" => "status",
        "email_start" => "email/start",
        "email_confirm" => "email/confirm",
        "phone_start" => "phone/start",
        "phone_pay" => "phone/pay",
        "phone_status" => "phone/status",
        "phone_sms" => "phone/sms",
        "phone_confirm" => "phone/confirm",
        "discoverability" => "discoverability",
        "contacts_discover" => "contacts/discover",
        "contacts_save" => "contacts/save",
        "contacts_list" => "contacts/list",
        "contact_address" => "contacts/address",
        other => unreachable!("unknown action {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every action maps to a route; a typo here would sign one thing
    /// and call another.
    #[test]
    fn every_action_has_a_route() {
        for action in [
            "status",
            "email_start",
            "email_confirm",
            "phone_start",
            "phone_pay",
            "phone_status",
            "phone_sms",
            "phone_confirm",
            "discoverability",
            "contacts_discover",
            "contacts_save",
            "contacts_list",
            "contact_address",
        ] {
            assert!(!action_path(action).is_empty());
        }
    }
}
