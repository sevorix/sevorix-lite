// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
pub struct Assets;
