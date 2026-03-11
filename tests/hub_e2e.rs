/// End-to-end tests for the SevorixHub API.
///
/// These tests hit the live hub server and require a valid auth token at
/// `~/.sevorix/hub_token` (i.e. `sevorix hub login` must have been run).
///
/// They are skipped automatically when no token is present, so they are safe
/// to include in CI without credentials.
///
/// Run explicitly:
///   cargo test --test hub_e2e
use sevorix_watchtower::hub::{DependencyRef, HubClient, PushRequest};

/// Unique prefix for all artifacts created by this test run.
/// Uses the current Unix timestamp so parallel runs don't collide.
fn run_prefix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("e2e-{}", ts)
}

/// Minimal valid JSON content for a policy artifact.
fn policy_content(id: &str) -> String {
    serde_json::json!({
        "id": id,
        "type": "Simple",
        "pattern": format!("test-pattern-{}", id),
        "action": "Block",
        "context": "Shell",
        "kill": false
    })
    .to_string()
}

/// Returns a HubClient, or None if no token is available (skip the test).
fn client_or_skip() -> Option<HubClient> {
    match HubClient::new(None) {
        Ok(c) => {
            // Load the token to verify it's actually present
            if sevorix_watchtower::hub::load_token().is_ok() {
                Some(c)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Basic push / pull / search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hub_e2e_basic_push_and_pull() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let name = format!("{}-basic", prefix);

    // Push
    let push_resp = client
        .push(PushRequest {
            name: name.clone(),
            version: "1.0.0".to_string(),
            description: Some("E2E basic push test".to_string()),
            tags: Some(vec!["e2e".to_string(), "test".to_string()]),
            content: policy_content("e2e-basic"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await
        .expect("push should succeed");

    assert_eq!(push_resp.name, name);
    assert_eq!(push_resp.version, "1.0.0");
    assert_eq!(push_resp.artifact_type, "artifact");
    assert!(push_resp.dependencies.is_empty());

    // Pull
    let pull_resp = client
        .pull(&name, "1.0.0")
        .await
        .expect("pull should succeed");

    assert_eq!(pull_resp.name, name);
    assert_eq!(pull_resp.version, "1.0.0");
    assert_eq!(pull_resp.artifact_type, "artifact");
    assert!(pull_resp.dependencies.is_empty());

    // Verify content round-trips correctly
    let content_val: serde_json::Value = serde_json::from_str(&policy_content("e2e-basic")).unwrap();
    assert_eq!(pull_resp.content, content_val);
}

#[tokio::test]
async fn test_hub_e2e_search_finds_pushed_artifact() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let name = format!("{}-searchable", prefix);

    client
        .push(PushRequest {
            name: name.clone(),
            version: "1.0.0".to_string(),
            description: Some("E2E search test".to_string()),
            tags: Some(vec!["e2e".to_string()]),
            content: policy_content("e2e-search"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await
        .expect("push should succeed");

    let search_resp = client
        .search(Some(&name), None)
        .await
        .expect("search should succeed");

    assert!(
        search_resp.results.iter().any(|r| r.name == name),
        "pushed artifact '{}' should appear in search results",
        name
    );
}

// ---------------------------------------------------------------------------
// Dependency declarations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hub_e2e_push_with_declared_dependency() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let dep_name = format!("{}-dep-base", prefix);
    let main_name = format!("{}-dep-consumer", prefix);

    // Push the dependency first
    client
        .push(PushRequest {
            name: dep_name.clone(),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: policy_content("e2e-dep-base"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await
        .expect("push base dep should succeed");

    // Push the consumer declaring the dependency
    let push_resp = client
        .push(PushRequest {
            name: main_name.clone(),
            version: "1.0.0".to_string(),
            description: Some("E2E dep consumer".to_string()),
            tags: None,
            content: policy_content("e2e-dep-consumer"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: Some(vec![DependencyRef {
                name: dep_name.clone(),
                version: "1.0.0".to_string(),
                required: true,
            }]),
        })
        .await
        .expect("push with dep should succeed");

    assert_eq!(push_resp.dependencies.len(), 1);
    assert_eq!(push_resp.dependencies[0].name, dep_name);
    assert_eq!(push_resp.dependencies[0].version, "1.0.0");
    assert!(push_resp.dependencies[0].required);

    // Pull and verify deps are returned
    let pull_resp = client
        .pull(&main_name, "1.0.0")
        .await
        .expect("pull should succeed");

    assert_eq!(pull_resp.dependencies.len(), 1);
    assert_eq!(pull_resp.dependencies[0].name, dep_name);
}

#[tokio::test]
async fn test_hub_e2e_dependency_must_exist() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();

    let result = client
        .push(PushRequest {
            name: format!("{}-nonexistent-dep-consumer", prefix),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: policy_content("e2e-nonexistent-dep"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: Some(vec![DependencyRef {
                name: format!("{}-does-not-exist", prefix),
                version: "9.9.9".to_string(),
                required: true,
            }]),
        })
        .await;

    assert!(result.is_err(), "push with nonexistent dep should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("does not exist") || err.contains("400"),
        "error should mention missing dep, got: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Artifact sets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hub_e2e_artifact_set_push_and_pull() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let member_a = format!("{}-set-member-a", prefix);
    let member_b = format!("{}-set-member-b", prefix);
    let set_name = format!("{}-set", prefix);

    // Push both members
    for (name, id) in [(&member_a, "e2e-set-a"), (&member_b, "e2e-set-b")] {
        client
            .push(PushRequest {
                name: name.clone(),
                version: "1.0.0".to_string(),
                description: None,
                tags: None,
                content: policy_content(id),
                visibility: Some("public".to_string()),
                artifact_type: Some("artifact".to_string()),
                dependencies: None,
            })
            .await
            .unwrap_or_else(|e| panic!("push member {} failed: {}", name, e));
    }

    // Push the set
    let push_resp = client
        .push(PushRequest {
            name: set_name.clone(),
            version: "1.0.0".to_string(),
            description: Some("E2E artifact set".to_string()),
            tags: Some(vec!["e2e".to_string(), "set".to_string()]),
            content: "{}".to_string(),
            visibility: Some("public".to_string()),
            artifact_type: Some("set".to_string()),
            dependencies: Some(vec![
                DependencyRef {
                    name: member_a.clone(),
                    version: "1.0.0".to_string(),
                    required: true,
                },
                DependencyRef {
                    name: member_b.clone(),
                    version: "1.0.0".to_string(),
                    required: true,
                },
            ]),
        })
        .await
        .expect("set push should succeed");

    assert_eq!(push_resp.artifact_type, "set");
    assert_eq!(push_resp.dependencies.len(), 2);

    let dep_names: Vec<&str> = push_resp.dependencies.iter().map(|d| d.name.as_str()).collect();
    assert!(dep_names.contains(&member_a.as_str()));
    assert!(dep_names.contains(&member_b.as_str()));

    // Pull the set and verify
    let pull_resp = client
        .pull(&set_name, "1.0.0")
        .await
        .expect("set pull should succeed");

    assert_eq!(pull_resp.artifact_type, "set");
    assert_eq!(pull_resp.dependencies.len(), 2);
}

#[tokio::test]
async fn test_hub_e2e_set_requires_at_least_one_dependency() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();

    let result = client
        .push(PushRequest {
            name: format!("{}-empty-set", prefix),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: "{}".to_string(),
            visibility: Some("public".to_string()),
            artifact_type: Some("set".to_string()),
            dependencies: None, // No members — should be rejected
        })
        .await;

    assert!(result.is_err(), "set with no deps should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("at least one member") || err.contains("400"),
        "error should mention missing members, got: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Yanking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hub_e2e_yank_and_unyank() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let name = format!("{}-yank-test", prefix);

    let push_resp = client
        .push(PushRequest {
            name: name.clone(),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: policy_content("e2e-yank"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await
        .expect("push should succeed");

    // Yank it
    client
        .yank(&push_resp.id, Some("test cleanup"))
        .await
        .expect("yank should succeed");

    // Search should no longer return it (yanked artifacts excluded by default)
    let search_resp = client
        .search(Some(&name), None)
        .await
        .expect("search should succeed");

    assert!(
        !search_resp.results.iter().any(|r| r.name == name),
        "yanked artifact should not appear in default search results"
    );

    // Unyank it
    client
        .unyank(&push_resp.id)
        .await
        .expect("unyank should succeed");

    // Should be findable again
    let search_resp = client
        .search(Some(&name), None)
        .await
        .expect("search should succeed");

    assert!(
        search_resp.results.iter().any(|r| r.name == name),
        "unyanked artifact should reappear in search results"
    );
}

#[tokio::test]
async fn test_hub_e2e_duplicate_version_rejected() {
    let client = match client_or_skip() {
        Some(c) => c,
        None => {
            eprintln!("SKIP: no hub token found");
            return;
        }
    };

    let prefix = run_prefix();
    let name = format!("{}-dup-version", prefix);

    client
        .push(PushRequest {
            name: name.clone(),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: policy_content("e2e-dup"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await
        .expect("first push should succeed");

    let result = client
        .push(PushRequest {
            name: name.clone(),
            version: "1.0.0".to_string(),
            description: None,
            tags: None,
            content: policy_content("e2e-dup"),
            visibility: Some("public".to_string()),
            artifact_type: Some("artifact".to_string()),
            dependencies: None,
        })
        .await;

    assert!(result.is_err(), "duplicate name@version should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("already exists") || err.contains("409"),
        "error should indicate conflict, got: {}",
        err
    );
}
