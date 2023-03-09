// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::key_chain::{AccountKeyChain, KeyChainId, KeyPurpose};
use crate::{WalletError, WalletResult};
use common::address::Address;
use common::chain::{ChainConfig, OutPoint, Transaction, TxOutput};
use common::primitives::{Id, Idable};
use std::collections::BTreeMap;
use std::sync::Arc;
use utxo::Utxo;
use wallet_storage::{Store, StoreTxRw, TransactionRw, Transactional, WalletStorageWrite};
use wallet_types::{TxState, WalletTx};

pub struct Account<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Arc<Store<B>>,
    key_chain: AccountKeyChain<B>,
    txs: BTreeMap<Id<Transaction>, WalletTx>,
    utxo: BTreeMap<OutPoint, Utxo>,
}

impl<B: storage::Backend> Account<B> {
    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
        id: KeyChainId,
        key_chain: AccountKeyChain<B>, // TODO remove
    ) -> WalletResult<Account<B>> {
        let txs = db.read_transactions()?;
        let utxo = db.read_utxo_set()?;

        // TODO load key_chain from database

        Ok(Account {
            chain_config,
            db,
            key_chain,
            txs,
            utxo,
        })
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
        key_chain: AccountKeyChain<B>,
    ) -> Account<B> {
        Account {
            chain_config,
            db,
            key_chain,
            txs: BTreeMap::new(),
            utxo: BTreeMap::new(),
        }
    }

    /// Get the id of this account
    pub fn get_id(&self) -> KeyChainId {
        self.key_chain.get_id()
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address(&mut self, purpose: KeyPurpose) -> WalletResult<Address> {
        Ok(self.key_chain.get_new_address(purpose)?)
    }

    #[allow(dead_code)] // TODO remove
    fn add_transaction(&mut self, tx: Transaction, state: TxState) -> WalletResult<()> {
        let tx_id = tx.get_id();

        if self.txs.contains_key(&tx_id) {
            return Err(WalletError::DuplicateTransaction(tx_id));
        }

        let mut db_tx = self.db.transaction_rw(None)?;

        let wallet_tx = WalletTx::new(tx, state);

        db_tx.set_transaction(&tx_id, &wallet_tx)?;
        db_tx.commit()?;

        self.txs.insert(tx_id, wallet_tx);

        // TODO add UTXO?

        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn delete_transaction(&mut self, tx_id: Id<Transaction>) -> WalletResult<()> {
        if !self.txs.contains_key(&tx_id) {
            return Err(WalletError::NoTransactionFound(tx_id));
        }

        let mut db_tx = self.db.transaction_rw(None)?;
        db_tx.del_transaction(&tx_id)?;
        db_tx.commit()?;

        self.txs.remove(&tx_id);

        // TODO remove UTXO?

        Ok(())
    }

    // TODO fix incompatibility between borrowing mut self and the database transaction
    #[allow(dead_code)] // TODO remove
    fn add_to_utxos(&mut self, tx: &Transaction, db_tx: &mut StoreTxRw<B>) -> WalletResult<()> {
        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                self.utxo.insert(outpoint.clone(), utxo.clone());
                db_tx.set_utxo(&outpoint, utxo)?;
            }
        }
        Ok(())
    }

    #[allow(dead_code)] // TODO remove
    fn is_available_for_spending(&self, _txo: &TxOutput) -> bool {
        // TODO implement
        true
    }

    #[allow(dead_code)] // TODO remove
    fn is_mine_or_watched(&self, _txo: &TxOutput) -> bool {
        // TODO implement
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_chain::MasterKeyChain;
    use common::chain::config::create_regtest;
    use common::chain::{GenBlock, Transaction};
    use common::primitives::{Idable, H256};
    use crypto::key::hdkd::child_number::ChildNumber;
    use wallet_storage::DefaultBackend;
    use wallet_types::TxState;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn account_transactions() {
        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), db.clone(), MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.create_account_key_chain(ChildNumber::ZERO_H).unwrap();

        let mut account = Account::new(config.clone(), db.clone(), key_chain);
        let id = account.get_id();

        let tx1 = Transaction::new(1, vec![], vec![], 0).unwrap();
        let tx2 = Transaction::new(2, vec![], vec![], 0).unwrap();
        let tx3 = Transaction::new(3, vec![], vec![], 0).unwrap();
        let tx4 = Transaction::new(4, vec![], vec![], 0).unwrap();

        let block_id: Id<GenBlock> = H256::from_low_u64_le(123).into();

        account.add_transaction(tx1.clone(), TxState::Confirmed(block_id)).unwrap();
        account.add_transaction(tx2.clone(), TxState::Conflicted(block_id)).unwrap();
        account.add_transaction(tx3.clone(), TxState::InMempool).unwrap();
        account.add_transaction(tx4.clone(), TxState::Inactive).unwrap();
        drop(account);

        // TODO load account key chain from database
        let key_chain = master_key_chain.create_account_key_chain(ChildNumber::ZERO_H).unwrap();
        let mut account =
            Account::load_from_database(config.clone(), db.clone(), id.clone(), key_chain).unwrap();

        assert_eq!(4, account.txs.len());
        assert_eq!(&tx1, account.txs.get(&tx1.get_id()).unwrap().get_tx());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx3, account.txs.get(&tx3.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());

        account.delete_transaction(tx1.get_id()).unwrap();
        account.delete_transaction(tx3.get_id()).unwrap();
        drop(account);

        // TODO load account key chain from database
        let key_chain = master_key_chain.create_account_key_chain(ChildNumber::ZERO_H).unwrap();
        let account =
            Account::load_from_database(config.clone(), db.clone(), id, key_chain).unwrap();

        assert_eq!(2, account.txs.len());
        assert_eq!(&tx2, account.txs.get(&tx2.get_id()).unwrap().get_tx());
        assert_eq!(&tx4, account.txs.get(&tx4.get_id()).unwrap().get_tx());
    }

    #[test]
    fn account_addresses() {
        let config = Arc::new(create_regtest());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());

        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(config.clone(), db.clone(), MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.create_account_key_chain(ChildNumber::ZERO_H).unwrap();

        let mut account = Account::new(config.clone(), db.clone(), key_chain);

        let test_vec = vec![
            (
                KeyPurpose::ReceiveFunds,
                "rmt14qdg6kvlkpfwcw6zjc3dlxpj0g6ddknf54evpv",
            ),
            (
                KeyPurpose::Change,
                "rmt1867l3cva9qprxny6yanula7k6scuj9xy9rv7m2",
            ),
            (
                KeyPurpose::ReceiveFunds,
                "rmt1vnqqfgfccs2sg7c0feptrw03qm8ejq5vqqvpql",
            ),
        ];

        for (purpose, address_str) in test_vec {
            let address = account.get_new_address(purpose).unwrap();
            assert_eq!(address.get(), address_str);
        }
    }
}
