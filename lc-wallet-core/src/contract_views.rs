//! What the contract verifier asks of a host, built from plain facts
//! (contracts, phase 1; covenant positions spec §5 rules 5 and 6).
//!
//! [`crate::contract_registration`] checks a relying party's description
//! against a [`WalletView`] and a [`ChainView`]. A host may implement both
//! over its own wallet, as the SideSwap app does. These are the same two
//! views built from what any wallet has at hand, its scripts, its balances
//! and a chain backend indexed by script, so that the rules that are easy to
//! get wrong are written once: which amount of an asset is a held token,
//! what a script's hash is, and how one history of a script says whether a
//! coin is there, whether it is in a block and what spent it (decisions 45
//! and 47 of the covenant positions decision log).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use elements::{AssetId, OutPoint, Script, Transaction};

use crate::contract_registration::{ChainOutput, ChainUnavailable, ChainView, WalletView};
use crate::contracts::script_hash;

/// The wallet as the role check sees it: a role is bound by a script that is
/// the wallet's or a token the wallet holds, never by the site's word.
#[derive(Debug, Clone, Default)]
pub struct FactsWalletView {
    script_hashes: BTreeSet<[u8; 32]>,
    tokens: BTreeSet<AssetId>,
}

impl FactsWalletView {
    /// `scripts`: every scriptPubKey the wallet has derived, used or not, so
    /// that a payout address handed to a site long ago and never paid is
    /// known. `balances`: what the wallet holds, per coin or per asset;
    /// amounts of one asset are added up. A position token and a lender token
    /// are issued as ONE unit, so the wallet holds a token when it holds
    /// exactly one unit of the asset. Two units are a balance of something
    /// else.
    pub fn new<'a>(scripts: impl IntoIterator<Item = &'a Script>, balances: impl IntoIterator<Item = (AssetId, u64)>) -> Self {
        let mut totals = BTreeMap::<AssetId, u64>::new();
        for (asset, amount) in balances {
            let total = totals.entry(asset).or_default();
            *total = total.saturating_add(amount);
        }
        FactsWalletView {
            script_hashes: scripts.into_iter().map(script_hash).collect(),
            tokens: totals.into_iter().filter(|(_, total)| *total == 1).map(|(asset, _)| asset).collect(),
        }
    }
}

impl WalletView for FactsWalletView {
    fn owns_script_hash(&self, hash: &[u8; 32]) -> bool {
        self.script_hashes.contains(hash)
    }

    fn holds_token(&self, asset: AssetId) -> bool {
        self.tokens.contains(&asset)
    }
}

/// A transaction in a script's history, as the chain backend has it.
#[derive(Debug, Clone)]
pub struct HistoryTx {
    pub tx: Transaction,
    /// In a block. A transaction still in the mempool is in the history too,
    /// unconfirmed.
    pub confirmed: bool,
}

/// A chain backend indexed by script, as an Electrum or an Esplora server is.
pub trait ScriptHistory {
    /// Every transaction that pays `script` or spends a coin of it, mempool
    /// included. `ChainUnavailable` when the backend cannot answer now.
    fn history(&self, script: &Script) -> Result<Vec<HistoryTx>, ChainUnavailable>;
}

/// The chain as the coin check sees it, answered from script histories. The
/// verifier names the script it expects at every coin, because it rebuilt
/// that script from the terms, and ONE history of that script says whether
/// the coin exists, whether it is in a block and what spent it. A claim script
/// is asked about once for every coin it holds, so a history is read once for
/// the life of the view: make one view per registration. A backend that cannot
/// answer is not remembered, so the next coin asks again.
pub struct HistoryChainView<'a> {
    backend: &'a dyn ScriptHistory,
    histories: RefCell<HashMap<Script, Vec<HistoryTx>>>,
}

impl<'a> HistoryChainView<'a> {
    pub fn new(backend: &'a dyn ScriptHistory) -> Self {
        HistoryChainView {
            backend,
            histories: RefCell::new(HashMap::new()),
        }
    }
}

impl ChainView for HistoryChainView<'_> {
    fn output(&self, outpoint: &OutPoint, script: &Script) -> Result<Option<ChainOutput>, ChainUnavailable> {
        if !self.histories.borrow().contains_key(script) {
            let history = self.backend.history(script)?;
            self.histories.borrow_mut().insert(script.clone(), history);
        }
        let histories = self.histories.borrow();
        let history = histories.get(script).expect("inserted above");

        // The transaction id is computed here, never taken from the backend.
        let Some(funding) = history.iter().find(|item| item.tx.txid() == outpoint.txid) else {
            return Ok(None);
        };
        let Some(txout) = funding.tx.output.get(outpoint.vout as usize) else {
            return Ok(None);
        };
        if txout.script_pubkey != *script {
            return Ok(None);
        }
        // A spend that is only in the mempool is a spend: the coin is no
        // longer where a description says it is.
        let spent_by = history
            .iter()
            .find(|item| item.tx.input.iter().any(|input| input.previous_output == *outpoint))
            .map(|item| item.tx.txid());
        Ok(Some(ChainOutput {
            txout: txout.clone(),
            confirmed: funding.confirmed,
            spent_by,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use elements::confidential::{Asset, Nonce, Value};
    use elements::{LockTime, Sequence, TxIn, TxOut};

    use super::*;

    const LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

    fn spk(tag: u8) -> Script {
        Script::from(vec![0x00, 0x14].into_iter().chain([tag; 20]).collect::<Vec<u8>>())
    }

    fn asset(byte: u8) -> AssetId {
        AssetId::from_str(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn tx(spends: &[OutPoint], pays: &[(Script, u64)]) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: spends
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    is_pegin: false,
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    asset_issuance: Default::default(),
                    witness: Default::default(),
                })
                .collect(),
            output: pays
                .iter()
                .map(|(script_pubkey, amount)| TxOut {
                    asset: Asset::Explicit(AssetId::from_str(LBTC).unwrap()),
                    value: Value::Explicit(*amount),
                    nonce: Nonce::Null,
                    script_pubkey: script_pubkey.clone(),
                    witness: Default::default(),
                })
                .collect(),
        }
    }

    /// A backend that knows only what each script's history is.
    #[derive(Default)]
    struct FakeBackend {
        histories: Mutex<HashMap<Script, Vec<HistoryTx>>>,
        asked: AtomicUsize,
        down: AtomicBool,
    }

    impl ScriptHistory for FakeBackend {
        fn history(&self, script: &Script) -> Result<Vec<HistoryTx>, ChainUnavailable> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(ChainUnavailable);
            }
            Ok(self.histories.lock().unwrap().get(script).cloned().unwrap_or_default())
        }
    }

    /// A script is the wallet's by its hash, whether it was ever paid or not,
    /// and a token is exactly one unit, counted over every coin of the asset.
    #[test]
    fn a_token_is_one_unit_and_a_script_is_known_by_its_hash() {
        let paid_once = spk(0x01);
        let never_paid = spk(0x02);
        let wallet = FactsWalletView::new(
            [&paid_once, &never_paid],
            [(asset(1), 1), (asset(2), 2), (asset(3), 0), (asset(4), 100_000_000), (asset(5), 1), (asset(5), 1)],
        );
        assert!(wallet.owns_script_hash(&script_hash(&paid_once)));
        assert!(wallet.owns_script_hash(&script_hash(&never_paid)));
        assert!(!wallet.owns_script_hash(&script_hash(&spk(0x03))));
        assert!(wallet.holds_token(asset(1)));
        for not_a_token in [asset(2), asset(3), asset(4), asset(5), asset(6)] {
            assert!(!wallet.holds_token(not_a_token), "{not_a_token}");
        }
    }

    /// One history of the script the verifier expects answers all three
    /// questions about a coin: is it there, is it in a block, what spent it.
    #[test]
    fn a_scripts_history_says_whether_a_coin_exists_is_confirmed_and_is_spent() {
        let covenant = spk(0x52);
        let elsewhere = spk(0x09);
        let funding = tx(&[], &[(covenant.clone(), 1_000_000), (elsewhere.clone(), 5)]);
        let coin = OutPoint::new(funding.txid(), 0);
        let backend = FakeBackend::default();
        backend.histories.lock().unwrap().insert(covenant.clone(), vec![HistoryTx { tx: funding.clone(), confirmed: true }]);

        let chain = HistoryChainView::new(&backend);
        let output = chain.output(&coin, &covenant).unwrap().expect("the coin is there");
        assert_eq!(output.txout, funding.output[0]);
        assert!(output.confirmed);
        assert_eq!(output.spent_by, None);

        // Not there: another transaction, an index past the end, and an
        // output of the right transaction that pays another script.
        let stranger = OutPoint::new(tx(&[], &[(covenant.clone(), 1)]).txid(), 0);
        assert!(chain.output(&stranger, &covenant).unwrap().is_none());
        assert!(chain.output(&OutPoint::new(funding.txid(), 7), &covenant).unwrap().is_none());
        assert!(chain.output(&OutPoint::new(funding.txid(), 1), &covenant).unwrap().is_none());
        // The script was asked about four times and read once; a script
        // nobody has paid is read, and is simply empty.
        assert_eq!(backend.asked.load(Ordering::SeqCst), 1);
        assert!(chain.output(&OutPoint::new(funding.txid(), 1), &spk(0x77)).unwrap().is_none());
        assert_eq!(backend.asked.load(Ordering::SeqCst), 2);

        // A spend still in the mempool is a spend, and a funding transaction
        // still in the mempool is not confirmed. A new view reads again.
        let spend = tx(&[coin], &[(covenant.clone(), 500_000)]);
        backend.histories.lock().unwrap().insert(
            covenant.clone(),
            vec![HistoryTx { tx: funding.clone(), confirmed: true }, HistoryTx { tx: spend.clone(), confirmed: false }],
        );
        assert_eq!(chain.output(&coin, &covenant).unwrap().unwrap().spent_by, None, "one view, one reading");
        let chain = HistoryChainView::new(&backend);
        assert_eq!(chain.output(&coin, &covenant).unwrap().unwrap().spent_by, Some(spend.txid()));
        let continued = chain.output(&OutPoint::new(spend.txid(), 0), &covenant).unwrap().expect("the continuing coin");
        assert!(!continued.confirmed);
        assert_eq!(continued.spent_by, None);
    }

    /// A backend that cannot answer is "ask again later", never "there is no
    /// such coin", and the failure is not remembered.
    #[test]
    fn an_unreachable_backend_is_unavailable_and_is_asked_again() {
        let covenant = spk(0x52);
        let funding = tx(&[], &[(covenant.clone(), 1_000_000)]);
        let coin = OutPoint::new(funding.txid(), 0);
        let backend = FakeBackend::default();
        backend.histories.lock().unwrap().insert(covenant.clone(), vec![HistoryTx { tx: funding, confirmed: true }]);
        backend.down.store(true, Ordering::SeqCst);
        let chain = HistoryChainView::new(&backend);
        assert!(matches!(chain.output(&coin, &covenant), Err(ChainUnavailable)));
        backend.down.store(false, Ordering::SeqCst);
        assert!(chain.output(&coin, &covenant).unwrap().is_some());
    }
}
