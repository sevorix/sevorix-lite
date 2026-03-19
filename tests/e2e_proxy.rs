// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

mod common;
use common::harness::TestHarness;
use common::upstream::MockUpstream;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};

fn make_proxied_client(proxy_url: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy_url).unwrap())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

async fn harness_with_empty_role() -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec![],
        is_dynamic: false,
    });
    h
}

async fn harness_with_block_policy(pattern: &str) -> TestHarness {
    let h = TestHarness::with_role(Some("test".to_string())).await;
    h.add_policy_direct(Policy {
        id: "block-p".to_string(),
        match_type: PolicyType::Simple(pattern.to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["block-p".to_string()],
        is_dynamic: false,
    });
    h
}

/// 1.1 — A safe GET request is forwarded to the upstream and returns the upstream body.
#[tokio::test]
async fn test_1_1_safe_request_passes_through() {
    let upstream = MockUpstream::start_any().await;
    let h = harness_with_empty_role().await;
    let proxied = make_proxied_client(&h.base_url());

    let resp = proxied
        .get(upstream.uri())
        .send()
        .await
        .expect("proxied GET failed");

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("upstream-ok"),
        "expected 'upstream-ok' in body, got: {body}"
    );
    upstream.assert_called().await;
}

/// 1.2 — A request whose body matches a Block policy receives 403 and never reaches upstream.
#[tokio::test]
async fn test_1_2_blocked_request_returns_403() {
    let upstream = MockUpstream::start_any().await;
    let h = harness_with_block_policy("DROP TABLE").await;
    let proxied = make_proxied_client(&h.base_url());

    let resp = proxied
        .post(upstream.uri())
        .body("DROP TABLE users")
        .send()
        .await
        .expect("proxied POST failed");

    assert_eq!(resp.status(), 403);
    upstream.assert_not_called().await;
}

/// 1.5 — A POST with a large payload (3 000 chars) is forwarded successfully.
#[tokio::test]
async fn test_1_5_large_payload_forwarded() {
    let upstream = MockUpstream::start_any().await;
    let h = harness_with_empty_role().await;
    let proxied = make_proxied_client(&h.base_url());

    let large_body = "x".repeat(3000);

    let resp = proxied
        .post(upstream.uri())
        .body(large_body)
        .send()
        .await
        .expect("proxied POST with large body failed");

    assert_eq!(resp.status(), 200);
    upstream.assert_called().await;
}

/// 1.6 — A POST with an empty body is forwarded successfully.
#[tokio::test]
async fn test_1_6_empty_body_forwarded() {
    let upstream = MockUpstream::start_any().await;
    let h = harness_with_empty_role().await;
    let proxied = make_proxied_client(&h.base_url());

    let resp = proxied
        .post(upstream.uri())
        .body("")
        .send()
        .await
        .expect("proxied POST with empty body failed");

    assert_eq!(resp.status(), 200);
    upstream.assert_called().await;
}

/// 1.7 — Ten concurrent safe GET requests all return 200.
#[tokio::test]
async fn test_1_7_concurrent_requests() {
    let upstream = MockUpstream::start_any().await;
    let h = harness_with_empty_role().await;
    let proxied = make_proxied_client(&h.base_url());

    let upstream_uri = upstream.uri();
    let futures: Vec<_> = (0..10)
        .map(|_| {
            let client = proxied.clone();
            let uri = upstream_uri.clone();
            async move {
                client
                    .get(&uri)
                    .send()
                    .await
                    .expect("concurrent GET failed")
                    .status()
            }
        })
        .collect();

    let statuses = futures_util::future::join_all(futures).await;

    for (i, status) in statuses.iter().enumerate() {
        assert_eq!(
            status.as_u16(),
            200,
            "request #{i} expected 200, got {status}"
        );
    }
}
