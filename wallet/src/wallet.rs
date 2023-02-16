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

use std::collections::BTreeMap;
use std::path::Path;

use crate::wallet_tx::{Pool, TxPools};
use common::chain::{OutPoint, Transaction, TxOutput};
use common::primitives::{Id, Idable};
use utxo::Utxo;
use wallet_storage::{
    TransactionRw, Transactional, WalletStorageImpl, WalletStorageTxRwImpl, WalletStorageWrite,
};

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet database error: {0}")]
    DatabaseError(wallet_storage::Error),
}
#[allow(dead_code)] // TODO remove
pub struct Wallet {
    db: WalletStorageImpl,
    txs: BTreeMap<Id<Transaction>, Transaction>,
    utxo: BTreeMap<OutPoint, Utxo>,
    tx_pools: TxPools,
}

impl Wallet {
    pub fn open_wallet_file(path: &Path) -> Result<Self, WalletError> {
        let db = WalletStorageImpl::new_from_path(path.to_path_buf())
            .map_err(WalletError::DatabaseError)?;

        Self::load_wallet(db)
    }

    pub fn open_wallet_in_memory() -> Result<Self, WalletError> {
        let db = WalletStorageImpl::new_in_memory().map_err(WalletError::DatabaseError)?;
        Self::load_wallet(db)
    }

    fn load_wallet(db: WalletStorageImpl) -> Result<Self, WalletError> {
        let txs = db.read_transactions().map_err(WalletError::DatabaseError)?;
        let utxo = db.read_utxo_set().map_err(WalletError::DatabaseError)?;
        let tx_pools = TxPools {
            unspent: Default::default(),
            spent: Default::default(),
            pending: Default::default(),
            dead: Default::default(),
        };
        Ok(Wallet {
            db,
            txs,
            utxo,
            tx_pools,
        })
    }

    pub fn get_database(&self) -> &WalletStorageImpl {
        &self.db
    }

    #[allow(dead_code)] // TODO remove
    fn add_wallet_transaction(&mut self, tx: Transaction, pool: Pool) -> Result<(), WalletError> {
        let tx_id = tx.get_id();

        let mut db_tx = self.db.transaction_rw(None).map_err(WalletError::DatabaseError)?;

        // TODO implement transaction pools
        match pool {
            Pool::Unspent => {
                debug_assert!(self.tx_pools.unspent.insert(tx_id));
                // self.add_to_utxos(&tx, &mut db_tx)?;
            }
            Pool::Spent => {
                debug_assert!(self.tx_pools.spent.insert(tx_id));
            }
            Pool::Unconfirmed => {
                debug_assert!(self.tx_pools.pending.insert(tx_id));
                // self.add_to_utxos(&tx, &mut db_tx)?;
            }
            Pool::Conflicted => {
                debug_assert!(self.tx_pools.dead.insert(tx_id));
            }
        }

        db_tx.set_transaction(&tx_id, &tx).map_err(WalletError::DatabaseError)?;
        db_tx.commit().map_err(WalletError::DatabaseError)?;

        self.txs.insert(tx_id, tx);

        Ok(())
    }

    // TODO fix incompatibility between borrowing mut self and the database transaction
    #[allow(dead_code)] // TODO remove
    fn add_to_utxos(
        &mut self,
        tx: &Transaction,
        db_tx: &mut WalletStorageTxRwImpl,
    ) -> Result<(), WalletError> {
        for (i, output) in tx.outputs().iter().enumerate() {
            // Check if this output belongs to this wallet or it is watched
            if self.is_available_for_spending(output) && self.is_mine_or_watched(output) {
                let outpoint = OutPoint::new(tx.get_id().into(), i as u32);
                let utxo = Utxo::new(output.clone(), false, utxo::UtxoSource::Mempool);
                self.utxo.insert(outpoint.clone(), utxo.clone());
                db_tx.set_utxo(&outpoint, utxo).map_err(WalletError::DatabaseError)?;
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
    use common::chain::Transaction;
    use std::path::PathBuf;

    #[test]
    fn in_memory_wallet() {
        let wallet = Wallet::open_wallet_in_memory();
        assert!(wallet.is_ok())
    }

    #[test]
    fn wallet_transactions() {
        // TODO fix this
        // pub const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
        pub const TARGET_TMPDIR: &str = ".";
        let mut wallet_path = PathBuf::from(TARGET_TMPDIR);
        wallet_path.push("wallet_transactions.sqlite");
        let mut wallet =
            Wallet::open_wallet_file(wallet_path.as_path()).expect("the wallet to load");

        let tx1 = Transaction::new(1, vec![], vec![], 0).unwrap();
        let tx2 = Transaction::new(2, vec![], vec![], 0).unwrap();
        let tx3 = Transaction::new(3, vec![], vec![], 0).unwrap();
        let tx4 = Transaction::new(4, vec![], vec![], 0).unwrap();

        wallet.add_wallet_transaction(tx1.clone(), Pool::Unspent).unwrap();
        wallet.add_wallet_transaction(tx2.clone(), Pool::Unconfirmed).unwrap();
        wallet.add_wallet_transaction(tx3.clone(), Pool::Spent).unwrap();
        wallet.add_wallet_transaction(tx4.clone(), Pool::Conflicted).unwrap();
        drop(wallet);

        let wallet = Wallet::open_wallet_file(wallet_path.as_path()).expect("the wallet to load");

        assert_eq!(4, wallet.txs.len());
        assert_eq!(&tx1, wallet.txs.get(&tx1.get_id()).unwrap());
        assert_eq!(&tx2, wallet.txs.get(&tx2.get_id()).unwrap());
        assert_eq!(&tx3, wallet.txs.get(&tx3.get_id()).unwrap());
        assert_eq!(&tx4, wallet.txs.get(&tx4.get_id()).unwrap());
    }
}
