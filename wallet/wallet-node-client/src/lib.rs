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

use handles_client::WalletHandlesClientError;
use node_traits::NodeInterface;
use rpc_client::NodeRpcError;

pub mod handles_client;
pub mod node_traits;
pub mod rpc_client;

pub async fn make_rpc_client(
    remote_socket_address: String,
) -> Result<impl NodeInterface, NodeRpcError> {
    rpc_client::NodeRpcClient::new(remote_socket_address).await
}

pub async fn make_handles_client(
    chainstate_handle: chainstate::ChainstateHandle,
) -> Result<impl NodeInterface, WalletHandlesClientError> {
    handles_client::WalletHandlesClient::new(chainstate_handle).await
}