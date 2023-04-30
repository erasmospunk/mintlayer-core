// Copyright (c) 2021-2023 RBB S.r.l
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

use iced::Element;

use crate::{backend_controller::NodeBackendController, Message};

pub mod main_menu;
pub mod main_widget;

pub fn view<'a>(
    backend_controller: &NodeBackendController,
) -> Element<'a, Message, iced::Renderer> {
    let c = iced::widget::column![
        main_menu::view(backend_controller),
        main_widget::view(backend_controller)
    ];

    c.into()
}
