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
use wallet_storage::WalletStorageImpl;

/// Wallet errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum WalletError {
    #[error("Wallet database error: {0}")]
    DatabaseError(wallet_storage::Error),
}

pub struct Wallet {
    db: WalletStorageImpl,
}

impl Wallet {
    pub fn open_wallet_file(path: &Path) -> Result<Self, WalletError> {
        let db = WalletStorageImpl::new_from_path(path.to_path_buf())
            .map_err(WalletError::DatabaseError)?;

        Ok(Wallet { db })
    }

    pub fn open_wallet_in_memory() -> Result<Self, WalletError> {
        let db = WalletStorageImpl::new_in_memory().map_err(WalletError::DatabaseError)?;

        Ok(Wallet { db })
    }

    pub fn get_database(&self) -> &WalletStorageImpl {
        &self.db
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
