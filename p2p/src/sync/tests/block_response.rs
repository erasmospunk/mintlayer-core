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

use std::sync::Arc;

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use crypto::random::Rng;
use p2p_test_utils::{chainstate_subsystem, create_n_blocks};
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    message::{Announcement, BlockListRequest, BlockResponse, HeaderListResponse, SyncMessage},
    sync::tests::helpers::SyncManagerHandle,
    types::peer_id::PeerId,
    P2pError,
};

// Messages from unknown peers are ignored.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn nonexistent_peer(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let chainstate = chainstate_subsystem(tf.into_chainstate()).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_chainstate(chainstate)
        .build()
        .await;

    let peer = PeerId::new();

    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));

    handle.assert_no_error().await;
    handle.assert_no_peer_manager_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn unrequested_block(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let chainstate = chainstate_subsystem(tf.into_chainstate()).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(chainstate)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("")).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn valid_response(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let num_blocks = rng.gen_range(2..10);
    let blocks = create_n_blocks(&mut tf, num_blocks);
    let chainstate = chainstate_subsystem(tf.into_chainstate()).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(chainstate)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    let ids = blocks.iter().map(|b| b.get_id()).collect();
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids))
    );

    for (i, block) in blocks.into_iter().enumerate() {
        handle.send_message(
            peer,
            SyncMessage::BlockResponse(BlockResponse::new(block.clone())),
        );

        assert_eq!(
            handle.announcement().await,
            Announcement::Block(block.header().clone())
        );

        // A peer would request headers after the last block.
        if i == num_blocks - 1 {
            let (sent_to, message) = handle.message().await;
            assert_eq!(peer, sent_to);
            assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
        }
    }

    handle.assert_no_error().await;
}
