//! The BetSimply house channel as a contract kind: `bs/channel/v5`
//! (contract standard §2b criterion J; Betsimply `_TASKS.md`, the b47
//! plan of 2026-09-18).
//!
//! A house channel is one covenant output whose script commits to the
//! channel's mutable state:
//!
//! ```text
//! script     = nums_script(TapBranch(program_root, TapData(state_hash)))
//! state_hash = SHA256("BSC1" ‖ channel_id ‖ seq(be4) ‖ player_bal(be8)
//!                     ‖ house_bal(be8, two's complement) ‖ owner_pk ‖ bet_pk ‖ pending)
//! ```
//!
//! The ten channel programs bake the house's parameters in at compile time
//! (the house key, its sink script hash, T_CHAL, T_REVEAL), so unlike the
//! lending kinds, whose leaf is one generic constant with the terms in a
//! data leaf, the program root is a constant per house and network, bound
//! by review to the published sources. [`PINS`] is that list. The wallet
//! cannot compile Simplicity; it accepts a channel only under a root it
//! pins, with the house parameters that root was compiled with, and
//! rebuilds the output script from the params and the state, which needs
//! SHA-256 alone.
//!
//! The immutable params of a channel are its id, the house's four
//! constants (in the pin as well, so a spec cannot name a house the root
//! was not built for), the owner key (the wallet's Liquid Connect identity
//! key, which binds the owner role), the bet key the browser holds, the
//! asset and the program root. Everything that moves with a bet — the
//! sequence number, both balances and the pending-bet digest — is the
//! state, 52 bytes, lower-case hex on the wire, so the contract id is
//! stable for the life of the account.
//!
//! Proven byte for byte against bs-test channel `7a02f38b…` at seq 0 and
//! seq 104 on 2026-09-18; the tests carry that vector, and derive both
//! pinned roots from the ten published CMRs of each program set.

use elements::hashes::{Hash as _, sha256};
use elements::taproot::{LeafVersion, TapLeafHash};
use elements::{AssetId, Script};

use crate::key::Network;
use crate::lending::{nums_script, tap_branch, tap_tagged};

/// `seq(4) ‖ player_bal(8) ‖ house_bal(8) ‖ pending(32)`.
pub const STATE_LEN: usize = 52;

/// The mutable state of a channel, as the covenant commits to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelState {
    pub seq: u32,
    /// Base units of the channel's asset owed to the player.
    pub player_bal: u64,
    /// Negative when the house owes the player (a win not yet checkpointed).
    pub house_bal: i64,
    /// The pending bet's digest; all zero when no bet is pending.
    pub pending: [u8; 32],
}

impl ChannelState {
    pub fn to_bytes(&self) -> [u8; STATE_LEN] {
        let mut out = [0u8; STATE_LEN];
        out[..4].copy_from_slice(&self.seq.to_be_bytes());
        out[4..12].copy_from_slice(&self.player_bal.to_be_bytes());
        out[12..20].copy_from_slice(&self.house_bal.to_be_bytes());
        out[20..].copy_from_slice(&self.pending);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != STATE_LEN {
            return None;
        }
        Some(ChannelState {
            seq: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            player_bal: u64::from_be_bytes(bytes[4..12].try_into().ok()?),
            house_bal: i64::from_be_bytes(bytes[12..20].try_into().ok()?),
            pending: bytes[20..].try_into().ok()?,
        })
    }

    /// The wire form: 104 lower-case hex characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Strictly the wire form; upper case or any other length is not it.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != STATE_LEN * 2 || text.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        Self::from_bytes(&hex::decode(text).ok()?)
    }
}

/// The immutable terms of a channel: what its contract id commits to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelTerms {
    pub asset: AssetId,
    pub channel_id: [u8; 32],
    /// The house's x-only key, compiled into the programs.
    pub house_pk: [u8; 32],
    /// SHA-256 of the house's sink scriptPubKey, compiled into the programs.
    pub house_sink: [u8; 32],
    /// The wallet's Liquid Connect identity key: the owner.
    pub owner_pk: [u8; 32],
    /// The browser's bet key.
    pub bet_pk: [u8; 32],
    /// The merkle root of the ten channel programs; must be a [`PINS`] entry.
    pub program_root: [u8; 32],
    /// Blocks the house must stay silent before the player may settle alone.
    pub t_chal: u32,
    pub t_reveal: u32,
}

/// `SHA256("BSC1" ‖ channel_id ‖ seq ‖ player_bal ‖ house_bal ‖ owner_pk ‖ bet_pk ‖ pending)`.
pub fn state_hash(terms: &ChannelTerms, state: &ChannelState) -> [u8; 32] {
    let mut m = Vec::with_capacity(4 + 32 + STATE_LEN + 64);
    m.extend_from_slice(b"BSC1");
    m.extend_from_slice(&terms.channel_id);
    m.extend_from_slice(&state.seq.to_be_bytes());
    m.extend_from_slice(&state.player_bal.to_be_bytes());
    m.extend_from_slice(&state.house_bal.to_be_bytes());
    m.extend_from_slice(&terms.owner_pk);
    m.extend_from_slice(&terms.bet_pk);
    m.extend_from_slice(&state.pending);
    sha256::Hash::hash(&m).to_byte_array()
}

/// The channel's scriptPubKey at `state`.
pub fn channel_script(terms: &ChannelTerms, state: &ChannelState) -> Script {
    let data_leaf = tap_tagged(b"TapData", &[&state_hash(terms, state)]);
    nums_script(tap_branch(terms.program_root, data_leaf))
}

/// A Simplicity tapleaf: leaf version `0xbe` over the program's CMR.
pub fn simplicity_tapleaf(cmr: &[u8; 32]) -> [u8; 32] {
    let script = Script::from(cmr.to_vec());
    TapLeafHash::from_script(&script, LeafVersion::from_u8(0xbe).expect("the Simplicity leaf version")).to_byte_array()
}

/// The ten channel programs in the order the program set publishes them
/// (`rolling-future` `covenant/measure/src/bs.rs` `CHANNEL_PROG_NAMES`).
pub const PROGRAM_NAMES: [&str; 10] = [
    "close",
    "checkpoint",
    "update",
    "settle",
    "settle_house",
    "rebind",
    "bet_claim",
    "bet_settle",
    "update_pending",
    "ch_topup",
];

/// The merkle root of the ten channel programs from their CMRs, in
/// [`PROGRAM_NAMES`] order: the fixed branch of the channel's tree, which
/// `TapBranch`es with the state's data leaf to make the output. This is
/// how a reviewer turns a published program set into a pin.
pub fn program_root(cmrs: &[[u8; 32]; 10]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = cmrs.iter().map(simplicity_tapleaf).collect();
    program_root_of_tapleaves(&leaves.try_into().expect("ten leaves"))
}

/// The same root from the ten tapleaf hashes (what the sidecar's `init`
/// reply lists), in [`PROGRAM_NAMES`] order. A house server that has no
/// Simplicity toolchain derives its channels' program root with this, so
/// the wallet and the server agree on one formula.
pub fn program_root_of_tapleaves(leaves: &[[u8; 32]; 10]) -> [u8; 32] {
    let l = leaves;
    let (close, checkpoint, update, settle, settle_house, rebind, bet_claim, bet_settle, update_pending, ch_topup) =
        (l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], l[8], l[9]);
    let b1 = tap_branch(close, checkpoint);
    let b2 = tap_branch(update, settle);
    let b3 = tap_branch(settle_house, tap_branch(rebind, ch_topup));
    let b4 = tap_branch(bet_claim, tap_branch(bet_settle, update_pending));
    tap_branch(tap_branch(b1, b2), tap_branch(b3, b4))
}

/// One house's program set on one network: the root the wallet accepts
/// and the parameters it was compiled with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HousePin {
    pub network: Network,
    /// The house's name, as the record is rendered ("BetSimply account").
    pub house: &'static str,
    pub program_root: [u8; 32],
    pub house_pk: [u8; 32],
    pub house_sink: [u8; 32],
    pub t_chal: u32,
    pub t_reveal: u32,
    /// Where the programs come from, for the review that binds the pin.
    pub sources: &'static str,
}

/// The program sets a wallet built from this source accepts. Adding a
/// house or a version is a code change and a review, on purpose.
///
/// Both roots were derived from the ten CMRs each instance's sidecar
/// compiled (`.cmr-cache-channel.json`) with [`program_root`], and the
/// testnet one was checked byte for byte against a live channel's outputs
/// (the tests). The house parameters are the ones each instance runs with.
pub const PINS: &[HousePin] = &[
    HousePin {
        network: Network::LiquidTestnet,
        house: "BetSimply",
        // bs-test, covenant v5 (Crossfire as game 6), 2026-09-15.
        program_root: hex_literal::hex!("44b292469244adf1c9211cb7a1d89f7f554bc81ccae93c9f3eea55a0c45ff7b1"),
        house_pk: hex_literal::hex!("165b912a7927918b831b3dfa36efb6ba80ae3c5b1a16f4fcfa297f97f74c7edd"),
        house_sink: hex_literal::hex!("41ade2f46159a246a8eb605610321cb5d1212a3a6913a66aa03c388835ed668c"),
        t_chal: 3,
        t_reveal: 2,
        sources: "https://github.com/sideswap-io/rolling-future/tree/8c3a8cc/covenant/bs",
    },
    HousePin {
        network: Network::Liquid,
        house: "BetSimply",
        // The mainnet instance, the same v5 program set compiled for its
        // own house key (read from its sidecar 2026-09-18; Scott to confirm
        // before a mainnet wallet ships with it).
        program_root: hex_literal::hex!("11fca8515f93456b5a85b2b3a1d3f5f1482ef94492b889c10677c51da73b0115"),
        house_pk: hex_literal::hex!("ad7ae0d0494b991bf723b06415eb3f6c433b3701e5f74bc395d9fc8775514e9b"),
        house_sink: hex_literal::hex!("19440aeccfe324a7c0b05bb9897097ba0e23b906376d72fcc6a4ce42a8f8356a"),
        t_chal: 3,
        t_reveal: 2,
        sources: "https://github.com/sideswap-io/rolling-future/tree/8c3a8cc/covenant/bs",
    },
];

/// The pin under `program_root`, if the wallet has one.
pub fn pin_for(program_root: &[u8; 32]) -> Option<&'static HousePin> {
    PINS.iter().find(|pin| pin.program_root == *program_root)
}

/// The pin these terms are accepted under: the root is pinned AND the
/// house parameters are the ones it was compiled with. `None` is
/// `leaf_mismatch`: the wallet will not describe an account under a house
/// the programs do not enforce.
pub fn pinned(terms: &ChannelTerms) -> Option<&'static HousePin> {
    pin_for(&terms.program_root)
        .filter(|pin| pin.house_pk == terms.house_pk && pin.house_sink == terms.house_sink && pin.t_chal == terms.t_chal && pin.t_reveal == terms.t_reveal)
}

/// SHA-256 of a house key's sink scriptPubKey (`OP_1 <32 bytes>`), as the
/// programs commit to it.
pub fn sink_hash(house_pk: &[u8; 32]) -> [u8; 32] {
    let mut spk = Vec::with_capacity(34);
    spk.extend_from_slice(&[0x51, 0x20]);
    spk.extend_from_slice(house_pk);
    sha256::Hash::hash(&spk).to_byte_array()
}

/// The real channel the kind was proven against: bs-test `7a02f38b…`
/// (wallet `2c12b569…`, covenant v5, opened 2026-09-18).
#[cfg(test)]
pub(crate) mod vectors {
    use super::*;
    use std::str::FromStr;

    pub const USDT_TESTNET: &str = "b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73";

    pub fn bs_test_channel() -> ChannelTerms {
        let pin = &PINS[0];
        ChannelTerms {
            asset: AssetId::from_str(USDT_TESTNET).unwrap(),
            channel_id: hex_literal::hex!("7a02f38b73d687ae8503f00e764faa14f4df8d9012a3710eef3cd3fd00000014"),
            house_pk: pin.house_pk,
            house_sink: pin.house_sink,
            owner_pk: hex_literal::hex!("2c12b569d954cf294c4309bdaed3afc26b904adcc966c31c9e3c7ddb3d9d4913"),
            bet_pk: hex_literal::hex!("d0b5f20e0f8d542ec3d9782110b709e14788251164e9c5bf5f8fda6426f7a7d1"),
            program_root: pin.program_root,
            t_chal: pin.t_chal,
            t_reveal: pin.t_reveal,
        }
    }

    /// The opening state (100 tUSDt deposited) and its funding address's script.
    pub fn seq0() -> ChannelState {
        ChannelState { seq: 0, player_bal: 100_00000000, house_bal: 0, pending: [0u8; 32] }
    }
    pub const SEQ0_SCRIPT: &str = "5120046bb740b4a40c10544c58522be9544131a76a4497793ede24bca2246eb8b86b";

    /// After a top-up and three checkpoints: the coin on chain at the time
    /// of writing, `be856370…:0`, 118 tUSDt, block 2622577.
    pub fn seq104() -> ChannelState {
        ChannelState { seq: 104, player_bal: 118_00000000, house_bal: 0, pending: [0u8; 32] }
    }
    pub const SEQ104_SCRIPT: &str = "5120dae122b393b2051fdc1845bde353a28a34de26e80c88e16d09e8f5a1d44ccdfe";
    pub const SEQ104_TXID: &str = "be8563700e00cf6907cd1901a0a65c05c18dd55bbc69f5f8d1ad9f999c69b423";
    pub const SEQ104_AMOUNT: u64 = 118_00000000;
}

#[cfg(test)]
mod tests {
    use super::vectors::*;
    use super::*;

    /// The ten CMRs each sidecar compiled (`.cmr-cache-channel.json`, in
    /// `PROGRAM_NAMES` order).
    const TESTNET_CMRS: [[u8; 32]; 10] = [
        hex_literal::hex!("b32863c708925e1cfaea51bd1b40ca1a7ec12b2508d75cd040f75b3888300ab9"),
        hex_literal::hex!("0875e1cd6f36176c62c6084f261770a651e2fa7e2753dc6a348a448c3415854b"),
        hex_literal::hex!("1fe6fe38689ff8907de535d7376d5b44cf79aecd110260d2b0197824bf279a1e"),
        hex_literal::hex!("409abd61feb96cb9f474ffb0c224b795b01f90a3469e11ebcbb8c7b4b76c0a0d"),
        hex_literal::hex!("2e630822efb917ff3769d248b6b84546134bb22a5764122588e9c67e1def1602"),
        hex_literal::hex!("dc5a6e7192257ea6f647355b7bebda01611028e672c65dd1f8178884eabb206b"),
        hex_literal::hex!("0fb77f4c606184e0296e874a755159d4ffd3f684c8b8fd7aa591570793a12aa8"),
        hex_literal::hex!("9631e6de8e32e9498547648d217d95b0a64a0941165c512fd344a11e30b25fb4"),
        hex_literal::hex!("8aa0872325ef71656bc01d95812b066f3276b852917a45090087b57eb248aa2a"),
        hex_literal::hex!("f1270d8f5d94769b08af7c13163d7c0eff2928dc2738a669b69c60e93de78fbd"),
    ];
    const MAINNET_CMRS: [[u8; 32]; 10] = [
        hex_literal::hex!("97a81d70227cefed4dc49e1fe23b2670e8dd49e48a8a48cfa9dd022790f501e8"),
        hex_literal::hex!("1389507b9d527efe3e4b2d73e81f960754c6aea1b9b942502ca755f75f42aa6d"),
        hex_literal::hex!("6f29b4b7ed30d189f177ed0f2623651fa107a77858c5e6d878ee270693592727"),
        hex_literal::hex!("9575a32c643772f94e4cdc63a91f90c7b5c622fe070cb9eb596652c4f8e2f411"),
        hex_literal::hex!("c72b8b1b81e4c4351502769ceb1e55779621eeae902c17b95d0333e15de552b1"),
        hex_literal::hex!("dc5a6e7192257ea6f647355b7bebda01611028e672c65dd1f8178884eabb206b"),
        hex_literal::hex!("1ce9c008a4f414d1f868949af29e2db3a8a91c224d938ada56942ae99ced8df8"),
        hex_literal::hex!("3c779448fe76e8a56bc55abb8338fed47e576106692ab809e3eddd01cde21661"),
        hex_literal::hex!("309e159f352b219009a5116784eff8f12484a959c3de49460ae1f4b7d28eeb85"),
        hex_literal::hex!("ba0bcf1a9f62bd31df817ea01865155aef2bb34f6113ccdf20601a6f9a417593"),
    ];

    /// Each pin is the root of its published program set, and the sink
    /// hash is the house key's `OP_1 <key>` script hashed.
    #[test]
    fn the_pins_are_the_roots_of_the_published_program_sets() {
        assert_eq!(program_root(&TESTNET_CMRS), PINS[0].program_root);
        assert_eq!(program_root(&MAINNET_CMRS), PINS[1].program_root);
        assert_ne!(PINS[0].program_root, PINS[1].program_root, "different house keys, different programs");
        for pin in PINS {
            assert_eq!(sink_hash(&pin.house_pk), pin.house_sink);
            assert_eq!(pin_for(&pin.program_root), Some(pin));
        }
        assert_eq!(pin_for(&[0u8; 32]), None);
    }

    /// The script rebuilt from the terms and the state is the one on chain:
    /// the funding address at seq 0 and the checkpointed coin at seq 104.
    #[test]
    fn a_real_channels_scripts_are_rebuilt_byte_for_byte() {
        let terms = bs_test_channel();
        assert_eq!(hex::encode(channel_script(&terms, &seq0()).as_bytes()), SEQ0_SCRIPT);
        assert_eq!(hex::encode(channel_script(&terms, &seq104()).as_bytes()), SEQ104_SCRIPT);
        // One byte of state, one different output.
        let mut off = seq104();
        off.player_bal += 1;
        assert_ne!(hex::encode(channel_script(&terms, &off).as_bytes()), SEQ104_SCRIPT);
        let mut off = seq104();
        off.house_bal = -1;
        assert_ne!(hex::encode(channel_script(&terms, &off).as_bytes()), SEQ104_SCRIPT);
    }

    /// The terms are accepted only under a pinned root with that root's
    /// house parameters.
    #[test]
    fn a_channel_is_pinned_by_its_root_and_its_house() {
        let terms = bs_test_channel();
        assert_eq!(pinned(&terms), Some(&PINS[0]));
        let mut lie = terms.clone();
        lie.program_root[0] ^= 1;
        assert_eq!(pinned(&lie), None, "an unreviewed program set");
        let mut lie = terms.clone();
        lie.house_pk = PINS[1].house_pk;
        assert_eq!(pinned(&lie), None, "the mainnet house under the testnet programs");
        let mut lie = terms.clone();
        lie.t_chal = 144;
        assert_eq!(pinned(&lie), None, "a T_CHAL the programs do not enforce");
        let mut lie = terms.clone();
        lie.house_sink[0] ^= 1;
        assert_eq!(pinned(&lie), None);
    }

    /// The state's wire form is 104 lower-case hex characters and nothing else.
    #[test]
    fn the_state_round_trips_and_reads_back_strictly() {
        let state = ChannelState { seq: 119, player_bal: 124_17607135, house_bal: -6_17607135, pending: [7u8; 32] };
        let hex_text = state.to_hex();
        assert_eq!(hex_text.len(), 104);
        assert!(hex_text.starts_with("00000077"), "{hex_text}");
        assert_eq!(&hex_text[24..40], hex::encode((-6_17607135i64).to_be_bytes()), "two's complement");
        assert_eq!(&ChannelState { house_bal: -1, ..state }.to_hex()[24..40], "ffffffffffffffff");
        assert_eq!(ChannelState::from_hex(&hex_text), Some(state));
        assert_eq!(ChannelState::from_hex(&hex_text.to_uppercase()), None);
        assert_eq!(ChannelState::from_hex(&hex_text[..102]), None);
        assert_eq!(ChannelState::from_hex(&format!("{hex_text}00")), None);
        assert_eq!(ChannelState::from_bytes(&[0u8; 51]), None);
        assert_eq!(seq0().to_hex(), format!("00000000{:016x}{:016x}{}", 100_00000000u64, 0u64, "00".repeat(32)));
    }
}
