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

use common::chain::Transaction;
use common::primitives::Id;
use std::collections::BTreeSet;

#[allow(dead_code)] // TODO remove
pub enum Pool {
    /// Unspent transaction
    Unspent,
    /// Spent transaction
    Spent, // spent in best chainPool
    /// Double-spent in a fork
    Conflicted,
    /// Unconfirmed transaction
    Unconfirmed,
}

#[allow(dead_code)] // TODO remove
pub struct TxPools {
    pub(crate) unspent: BTreeSet<Id<Transaction>>,
    pub(crate) spent: BTreeSet<Id<Transaction>>,
    pub(crate) pending: BTreeSet<Id<Transaction>>,
    pub(crate) dead: BTreeSet<Id<Transaction>>,
}

#[allow(dead_code)] // TODO remove
pub struct WalletTx {
    pool: Pool,
    tx: Transaction,
}

// TODO implement serialization for WalletTx
