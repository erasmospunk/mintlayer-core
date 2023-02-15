// Copyright (c) 2022 RBB S.r.l
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

use std::{iter, sync::Arc};

use common::{chain::config::create_unit_test_config, primitives::Idable};
use p2p_test_utils::{create_block, create_n_blocks, TestBlockInfo};

use crate::{
    net::default_backend::types::PeerId,
    sync::{tests::helpers::SyncManagerHandle, BlockListRequest, HeaderListResponse, SyncMessage},
};

// Messages from unknown peers are ignored.
#[tokio::test]
async fn nonexistent_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(Vec::new())),
    );
}

#[tokio::test]
async fn header_count_limit_exceeded() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    let headers = iter::repeat(block.header().clone()).take(2001).collect();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(score, 20);
}

#[tokio::test]
async fn unordered_headers() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        3,
    );
    // Skip the header in the middle.
    let headers = blocks
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, b)| b.header().clone())
        .collect();

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(score, 20);
}

#[tokio::test]
async fn disconnected_headers() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        3,
    )
    .into_iter()
    .skip(1)
    .map(|b| b.header().clone())
    .collect();

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(score, 20);
}

#[tokio::test]
async fn valid_headers() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        3,
    );
    let headers = blocks.iter().map(|b| b.header().clone()).collect();

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(
            blocks.into_iter().map(|b| b.get_id()).collect()
        ))
    );
}
