// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use anyhow::Result;
use std::path::PathBuf;

/// Trait defining artifact storage operations.
pub trait ArtifactStore: Send + Sync {
    /// Store artifact bytes under the given ID. Returns the resolved file path/object key.
    fn store(
        &self,
        id: &str,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<String>> + Send;
    /// Retrieve artifact bytes from the given file path/object key.
    fn retrieve(
        &self,
        file_path: &str,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// Filesystem-backed artifact store for local development.
#[derive(Clone)]
pub struct FilesystemStore {
    base_dir: PathBuf,
}

impl FilesystemStore {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", id))
    }
}

impl ArtifactStore for FilesystemStore {
    async fn store(&self, id: &str, data: &[u8]) -> Result<String> {
        let path = self.path_for(id);
        tokio::fs::write(&path, data).await?;
        Ok(path.to_string_lossy().into_owned())
    }

    async fn retrieve(&self, file_path: &str) -> Result<Vec<u8>> {
        let data = tokio::fs::read(file_path).await?;
        Ok(data)
    }
}

/// Azure Blob Storage-backed artifact store for production.
/// Uses the Azure Blob Storage REST API via reqwest.
#[derive(Clone)]
pub struct AzureBlobStore {
    account: String,
    container: String,
    client: reqwest::Client,
    /// Azure access token (obtained via Managed Identity IMDS or explicit override)
    access_token: Option<String>,
}

impl AzureBlobStore {
    /// Create a new Azure Blob store for the given storage account and container.
    /// In Azure Container Apps, the access token is automatically available via IMDS.
    pub fn new(account: impl Into<String>, container: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            container: container.into(),
            client: reqwest::Client::new(),
            access_token: None,
        }
    }

    /// Create an Azure Blob store with an explicit access token (useful for testing).
    pub fn with_token(
        account: impl Into<String>,
        container: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Self {
        Self {
            account: account.into(),
            container: container.into(),
            client: reqwest::Client::new(),
            access_token: Some(access_token.into()),
        }
    }

    /// Get the REST URL for a blob.
    fn blob_url(&self, key: &str) -> String {
        format!(
            "https://{}.blob.core.windows.net/{}/{}",
            self.account, self.container, key
        )
    }

    /// Get an access token from the configured value or the Azure IMDS Managed Identity endpoint.
    async fn get_access_token(&self) -> Result<String> {
        if let Some(ref token) = self.access_token {
            return Ok(token.clone());
        }

        // Fetch token from Azure IMDS (Container Apps / VM / AKS with Managed Identity)
        let metadata_url = "http://169.254.169.254/metadata/identity/oauth2/token\
             ?api-version=2018-02-01&resource=https://storage.azure.com/";
        let response = self
            .client
            .get(metadata_url)
            .header("Metadata", "true")
            .send()
            .await?;

        let json: serde_json::Value = response.json().await?;
        let token = json["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access_token in IMDS response"))?
            .to_string();

        Ok(token)
    }
}

impl ArtifactStore for AzureBlobStore {
    async fn store(&self, id: &str, data: &[u8]) -> Result<String> {
        let key = format!("artifacts/{}.json", id);
        let token = self.get_access_token().await?;

        let response = self
            .client
            .put(self.blob_url(&key))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-ms-version", "2020-10-02")
            .body(data.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Azure Blob upload failed: {} - {}", status, body);
        }

        Ok(key)
    }

    async fn retrieve(&self, file_path: &str) -> Result<Vec<u8>> {
        let token = self.get_access_token().await?;

        let response = self
            .client
            .get(self.blob_url(file_path))
            .header("Authorization", format!("Bearer {}", token))
            .header("x-ms-version", "2020-10-02")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Azure Blob download failed: {} - {}", status, body);
        }

        let data = response.bytes().await?;
        Ok(data.to_vec())
    }
}

/// Enum-based store for runtime dispatch without dyn trait.
#[derive(Clone)]
pub enum Store {
    Filesystem(FilesystemStore),
    AzureBlob(AzureBlobStore),
}

impl ArtifactStore for Store {
    async fn store(&self, id: &str, data: &[u8]) -> Result<String> {
        match self {
            Store::Filesystem(fs) => fs.store(id, data).await,
            Store::AzureBlob(az) => az.store(id, data).await,
        }
    }

    async fn retrieve(&self, file_path: &str) -> Result<Vec<u8>> {
        match self {
            Store::Filesystem(fs) => fs.retrieve(file_path).await,
            Store::AzureBlob(az) => az.retrieve(file_path).await,
        }
    }
}

impl Store {
    pub fn filesystem(base_dir: impl Into<PathBuf>) -> Self {
        Store::Filesystem(FilesystemStore::new(base_dir))
    }

    pub fn azure_blob(account: impl Into<String>, container: impl Into<String>) -> Self {
        Store::AzureBlob(AzureBlobStore::new(account, container))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // =========================================================================
    // FilesystemStore tests
    // =========================================================================

    #[tokio::test]
    async fn test_filesystem_store_creates_file() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let id = "test-artifact";
        let data = b"{\"test\": \"data\"}";

        let result = store.store(id, data).await;
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.contains("test-artifact.json"));
        assert!(fs::metadata(&path).is_ok(), "file should exist");
    }

    #[tokio::test]
    async fn test_filesystem_store_retrieve_data() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let id = "retrieve-test";
        let original_data = b"{\"key\": \"value\"}";

        store
            .store(id, original_data)
            .await
            .expect("store should succeed");
        let retrieved = store
            .retrieve(&dir.path().join(format!("{}.json", id)).to_string_lossy())
            .await
            .expect("retrieve should succeed");

        assert_eq!(retrieved, original_data);
    }

    #[tokio::test]
    async fn test_filesystem_store_overwrites_existing() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let id = "overwrite-test";

        store
            .store(id, b"original data")
            .await
            .expect("store should succeed");

        store
            .store(id, b"new data")
            .await
            .expect("store should succeed");

        let retrieved = store
            .retrieve(&dir.path().join(format!("{}.json", id)).to_string_lossy())
            .await
            .expect("retrieve should succeed");

        assert_eq!(retrieved, b"new data");
    }

    #[tokio::test]
    async fn test_filesystem_store_retrieve_nonexistent_fails() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let result = store.retrieve("/nonexistent/path/file.json").await;
        assert!(result.is_err(), "retrieving nonexistent file should fail");
    }

    #[tokio::test]
    async fn test_filesystem_store_path_for_format() {
        let store = FilesystemStore::new("/tmp/test");

        let path = store.path_for("my-id");
        assert_eq!(path.to_string_lossy(), "/tmp/test/my-id.json");
    }

    #[tokio::test]
    async fn test_filesystem_store_empty_data() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let id = "empty-test";
        let data = b"";

        let result = store.store(id, data).await;
        assert!(result.is_ok(), "storing empty data should succeed");
    }

    #[tokio::test]
    async fn test_filesystem_store_binary_data() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = FilesystemStore::new(dir.path());

        let id = "binary-test";
        let data: &[u8] = &[0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE];

        store.store(id, data).await.expect("store should succeed");
        let retrieved = store
            .retrieve(&dir.path().join(format!("{}.json", id)).to_string_lossy())
            .await
            .expect("retrieve should succeed");

        assert_eq!(retrieved, data);
    }

    // =========================================================================
    // Store enum tests
    // =========================================================================

    #[tokio::test]
    async fn test_store_filesystem_variant() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Store::filesystem(dir.path());

        let id = "enum-test";
        let data = b"test data";

        let path = store.store(id, data).await.expect("store should succeed");
        let retrieved = store
            .retrieve(&path)
            .await
            .expect("retrieve should succeed");

        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_store_azure_blob_variant_creation() {
        let store = Store::azure_blob("my-account", "my-container");
        match store {
            Store::AzureBlob(_) => (),
            _ => panic!("expected AzureBlob variant"),
        }
    }

    // =========================================================================
    // AzureBlobStore tests (non-network)
    // =========================================================================

    #[test]
    fn test_azure_blob_store_new() {
        let store = AzureBlobStore::new("my-account", "my-container");
        assert_eq!(store.account, "my-account");
        assert_eq!(store.container, "my-container");
        assert!(store.access_token.is_none());
    }

    #[test]
    fn test_azure_blob_store_with_token() {
        let store = AzureBlobStore::with_token("my-account", "my-container", "my-token");
        assert_eq!(store.account, "my-account");
        assert_eq!(store.container, "my-container");
        assert_eq!(store.access_token, Some("my-token".to_string()));
    }

    #[test]
    fn test_azure_blob_url() {
        let store = AzureBlobStore::new("myaccount", "artifacts");
        let url = store.blob_url("artifacts/test.json");
        assert_eq!(
            url,
            "https://myaccount.blob.core.windows.net/artifacts/artifacts/test.json"
        );
    }

    #[test]
    fn test_azure_blob_url_contains_account_and_container() {
        let store = AzureBlobStore::new("storageacct", "mycontainer");
        let url = store.blob_url("some/key.json");
        assert!(url.contains("storageacct"));
        assert!(url.contains("mycontainer"));
        assert!(url.contains("some/key.json"));
        assert!(url.starts_with("https://"));
        assert!(url.contains(".blob.core.windows.net"));
    }

    // Note: Testing get_access_token requires network access or mocking,
    // which is beyond the scope of unit tests. The store/retrieve operations
    // also require network for Azure Blob, so they're tested via integration tests.
}
