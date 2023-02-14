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

use crate::wallet_tx::Pool;
use common::chain::{OutPoint, Transaction};
use common::primitives::{Id, Idable};
use utxo::Utxo;
use wallet_storage::{WalletStorageImpl, WalletStorageWrite};

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet database error: {0}")]
    DatabaseError(wallet_storage::Error),
}

pub struct Wallet {
    db: WalletStorageImpl,
    txs: BTreeMap<Id<Transaction>, Transaction>,
    utxo: BTreeMap<OutPoint, Utxo>,
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
        let txs = BTreeMap::new(); // TODO
        let utxo = db.read_utxo_set().map_err(WalletError::DatabaseError)?;
        Ok(Wallet { db, txs, utxo })
    }

    pub fn get_database(&self) -> &WalletStorageImpl {
        &self.db
    }

    fn add_wallet_transaction(&mut self, tx: Transaction, pool: Pool) -> Result<(), WalletError> {
        let tx_id = tx.get_id();

        // TODO implement transaction pools
        match pool {
            Pool::Unspent => {
                // debug_assert!(self.unspent.insert(tx.get_tx_id(), tx).is_none());
                Self::add_to_utxos(&tx)
            }
            Pool::Spent => {
                // debug_assert!(self.spent.insert(tx.get_tx_id(), tx).is_none());
            }
            Pool::Unconfirmed => {
                // debug_assert!(self.pending.insert(tx.get_tx_id(), tx).is_none());
                Self::add_to_utxos(&tx)
            }
            Pool::Conflicted => {
                // debug_assert!(self.dead.insert(tx.get_tx_id(), tx).is_none());
            }
        }

        self.db.set_transaction(&tx_id, &tx).map_err(WalletError::DatabaseError)?;
        self.txs.insert(tx_id, tx);

        Ok(())
    }

    fn add_to_utxos(tx: &Transaction) {
        for output in tx.outputs() {
            // Check if this output belongs to this wallet or it is watched
            // if is_available_for_spending(output) && is_mine_or_watched(output) {
            //     self.utxo.insert
            // }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_wallet() {
        let wallet = Wallet::open_wallet_in_memory();
        assert!(wallet.is_ok())
    }
}
