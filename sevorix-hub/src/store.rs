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

/// Google Cloud Storage-backed artifact store for production.
/// Uses the GCS JSON API via reqwest for object storage.
#[derive(Clone)]
pub struct GcsStore {
    bucket: String,
    client: reqwest::Client,
    /// GCP access token (obtained via Workload Identity or service account)
    access_token: Option<String>,
}

impl GcsStore {
    /// Create a new GCS store for the given bucket.
    /// In Cloud Run, the access token is automatically available via metadata server.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            client: reqwest::Client::new(),
            access_token: None,
        }
    }

    /// Create a GCS store with an explicit access token.
    pub fn with_token(bucket: impl Into<String>, access_token: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            client: reqwest::Client::new(),
            access_token: Some(access_token.into()),
        }
    }

    /// Get the GCS object URL for a given key.
    fn object_url(&self, key: &str) -> String {
        format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}",
            self.bucket,
            urlencoding::encode(key)
        )
    }

    /// Get the upload URL for a given key.
    fn upload_url(&self, key: &str) -> String {
        format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.bucket,
            urlencoding::encode(key)
        )
    }

    /// Get an access token, either from the configured value or from the GCP metadata server.
    async fn get_access_token(&self) -> Result<String> {
        if let Some(ref token) = self.access_token {
            return Ok(token.clone());
        }

        // Fetch token from GCP metadata server (Cloud Run / GKE)
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let response = self
            .client
            .get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;

        let json: serde_json::Value = response.json().await?;
        let token = json["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in metadata response"))?
            .to_string();

        Ok(token)
    }
}

impl ArtifactStore for GcsStore {
    async fn store(&self, id: &str, data: &[u8]) -> Result<String> {
        let key = format!("artifacts/{}.json", id);
        let token = self.get_access_token().await?;

        let response = self
            .client
            .post(self.upload_url(&key))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(data.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GCS upload failed: {} - {}", status, body);
        }

        // Return the object key as the "file path"
        Ok(key)
    }

    async fn retrieve(&self, file_path: &str) -> Result<Vec<u8>> {
        let token = self.get_access_token().await?;

        let response = self
            .client
            .get(self.object_url(file_path))
            .header("Authorization", format!("Bearer {}", token))
            .query(&[("alt", "media")])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GCS download failed: {} - {}", status, body);
        }

        let data = response.bytes().await?;
        Ok(data.to_vec())
    }
}

/// URL encoding module for GCS object names.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}

/// Enum-based store for runtime dispatch without dyn trait.
#[derive(Clone)]
pub enum Store {
    Filesystem(FilesystemStore),
    Gcs(GcsStore),
}

impl ArtifactStore for Store {
    async fn store(&self, id: &str, data: &[u8]) -> Result<String> {
        match self {
            Store::Filesystem(fs) => fs.store(id, data).await,
            Store::Gcs(gcs) => gcs.store(id, data).await,
        }
    }

    async fn retrieve(&self, file_path: &str) -> Result<Vec<u8>> {
        match self {
            Store::Filesystem(fs) => fs.retrieve(file_path).await,
            Store::Gcs(gcs) => gcs.retrieve(file_path).await,
        }
    }
}

impl Store {
    pub fn filesystem(base_dir: impl Into<PathBuf>) -> Self {
        Store::Filesystem(FilesystemStore::new(base_dir))
    }

    pub fn gcs(bucket: impl Into<String>) -> Self {
        Store::Gcs(GcsStore::new(bucket))
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

        // First write
        store
            .store(id, b"original data")
            .await
            .expect("store should succeed");

        // Second write (overwrite)
        store
            .store(id, b"new data")
            .await
            .expect("store should succeed");

        // Should have new data
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
    fn test_store_gcs_variant_creation() {
        // Just test that we can create the variant (no network calls)
        let store = Store::gcs("my-bucket");
        match store {
            Store::Gcs(_) => (),
            _ => panic!("expected Gcs variant"),
        }
    }

    // =========================================================================
    // GcsStore tests (non-network)
    // =========================================================================

    #[test]
    fn test_gcs_store_new() {
        let store = GcsStore::new("test-bucket");
        assert_eq!(store.bucket, "test-bucket");
        assert!(store.access_token.is_none());
    }

    #[test]
    fn test_gcs_store_with_token() {
        let store = GcsStore::with_token("bucket-name", "my-token");
        assert_eq!(store.bucket, "bucket-name");
        assert_eq!(store.access_token, Some("my-token".to_string()));
    }

    #[test]
    fn test_gcs_object_url() {
        let store = GcsStore::new("my-bucket");
        let url = store.object_url("artifacts/test.json");
        assert!(url.contains("my-bucket"));
        assert!(url.contains("artifacts%2Ftest.json"));
    }

    #[test]
    fn test_gcs_upload_url() {
        let store = GcsStore::new("my-bucket");
        let url = store.upload_url("artifacts/new.json");
        assert!(url.contains("upload"));
        assert!(url.contains("my-bucket"));
        assert!(url.contains("artifacts%2Fnew.json"));
    }

    // Note: Testing get_access_token requires network access or mocking,
    // which is beyond the scope of unit tests. The store/retrieve operations
    // also require network for GCS, so they're tested via integration tests.
}
