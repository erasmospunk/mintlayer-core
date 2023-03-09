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

use std::path::Path;
use std::sync::Arc;

use crate::key_chain::{KeyChainError, MasterKeyChain};
use common::chain::config::create_regtest;
use common::chain::{ChainConfig, Transaction};
use common::primitives::Id;
use wallet_storage::{DefaultBackend, Store};

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet database error: {0}")]
    DatabaseError(#[from] wallet_storage::Error),
    #[error("Transaction already present: {0}")]
    DuplicateTransaction(Id<Transaction>),
    #[error("No transaction found: {0}")]
    NoTransactionFound(Id<Transaction>),
    #[error("Key chain error: {0}")]
    KeyChainError(#[from] KeyChainError),
}

/// Result type used for the wallet
pub type WalletResult<T> = Result<T, WalletError>;

#[allow(dead_code)] // TODO remove
pub struct Wallet<B: storage::Backend> {
    chain_config: Arc<ChainConfig>,
    db: Arc<Store<B>>,
    key_chain: MasterKeyChain<B>,
}

pub fn open_wallet_file<P: AsRef<Path>>(
    chain_config: Arc<ChainConfig>,
    path: P,
) -> WalletResult<Wallet<DefaultBackend>> {
    let db = Arc::new(Store::new(DefaultBackend::new(path))?);

    Wallet::load_wallet(chain_config, db)
}

pub fn open_wallet_in_memory(
    chain_config: Arc<ChainConfig>,
) -> WalletResult<Wallet<DefaultBackend>> {
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory())?);

    Wallet::load_wallet(chain_config, db)
}

impl<B: storage::Backend> Wallet<B> {
    fn load_wallet(chain_config: Arc<ChainConfig>, db: Arc<Store<B>>) -> WalletResult<Self> {
        let key_chain = MasterKeyChain::load_from_database(chain_config.clone(), db.clone())?;
        Ok(Wallet {
            chain_config,
            db,
            key_chain,
        })
    }

    pub fn get_database(&self) -> &Store<B> {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_wallet() {
        let config = Arc::new(create_regtest());
        let wallet = open_wallet_in_memory(config);
        assert!(wallet.is_ok())
    }
}
