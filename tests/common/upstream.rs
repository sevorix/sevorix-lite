use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

/// A mock upstream HTTP server for proxy tests.
pub struct MockUpstream {
    pub server: MockServer,
}

impl MockUpstream {
    /// Start a mock upstream that returns 200 OK for all GET requests.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("upstream-ok"))
            .mount(&server)
            .await;
        MockUpstream { server }
    }

    /// Start a mock upstream that returns 200 OK for ALL methods/paths.
    pub async fn start_any() -> Self {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_string("upstream-ok"))
            .mount(&server)
            .await;
        MockUpstream { server }
    }

    /// The base URL of this mock server (e.g. "http://127.0.0.1:PORT").
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Assert that exactly `n` requests were received by the mock.
    pub async fn assert_received(&self, n: u64) {
        assert_eq!(
            self.server.received_requests().await.unwrap().len() as u64,
            n,
            "MockUpstream: expected {} requests, got different count",
            n
        );
    }

    /// Assert that at least one request was received.
    pub async fn assert_called(&self) {
        let reqs = self.server.received_requests().await.unwrap();
        assert!(
            !reqs.is_empty(),
            "MockUpstream: expected at least 1 request, got 0"
        );
    }

    /// Assert that no requests were received (request was blocked before upstream).
    pub async fn assert_not_called(&self) {
        let reqs = self.server.received_requests().await.unwrap();
        assert!(
            reqs.is_empty(),
            "MockUpstream: expected 0 requests, got {}",
            reqs.len()
        );
    }
}
