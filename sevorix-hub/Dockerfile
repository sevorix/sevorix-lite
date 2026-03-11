# Build stage for sevorix-hub
FROM rust:slim-bookworm AS builder

WORKDIR /usr/src/sevorix

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY sevorix-core/Cargo.toml ./sevorix-core/
COPY sevorix-hub/Cargo.toml ./sevorix-hub/
COPY sevorix-ebpf-common/Cargo.toml ./sevorix-ebpf-common/
COPY sevorix-ebpf/Cargo.toml ./sevorix-ebpf/

# Create minimal source structure for cargo to resolve dependencies
# Root package (sevorix_watchtower)
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
# sevorix-core (lib) - empty lib is valid
RUN mkdir -p sevorix-core/src && touch sevorix-core/src/lib.rs
# sevorix-ebpf-common (lib) - workspace member, needed for dep graph resolution
RUN mkdir -p sevorix-ebpf-common/src && touch sevorix-ebpf-common/src/lib.rs
# sevorix-ebpf (bin) - workspace member, needed for dep graph resolution
RUN mkdir -p sevorix-ebpf/src && echo "fn main() {}" > sevorix-ebpf/src/main.rs
# sevorix-hub (lib + bin) - use dummy files that compile but don't need real dependencies
RUN mkdir -p sevorix-hub/src && \
    echo "pub mod db; pub mod routes; pub mod store; pub mod error; pub mod audit; pub mod auth; pub mod models;" > sevorix-hub/src/lib.rs && \
    echo "" > sevorix-hub/src/db.rs && \
    echo "" > sevorix-hub/src/routes.rs && \
    echo "" > sevorix-hub/src/store.rs && \
    echo "" > sevorix-hub/src/error.rs && \
    echo "" > sevorix-hub/src/audit.rs && \
    echo "" > sevorix-hub/src/auth.rs && \
    echo "" > sevorix-hub/src/models.rs && \
    echo "fn main() {}" > sevorix-hub/src/main.rs

# Download and cache dependencies
RUN cargo fetch

# Now copy the actual source files (this invalidates the cache from here on)
COPY sevorix-core/src ./sevorix-core/src
COPY sevorix-hub/src ./sevorix-hub/src
COPY sevorix-hub/migrations ./sevorix-hub/migrations

# Build the actual binary
RUN cargo build --release -p sevorix-hub

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /usr/src/sevorix/target/release/sevorix-hub /usr/local/bin/sevorix-hub

# Copy migrations (needed for sqlx::migrate!)
COPY --from=builder /usr/src/sevorix/sevorix-hub/migrations ./migrations

# Create non-root user for security
RUN useradd -r -s /bin/false sevorix && \
    chown -R sevorix:sevorix /app
USER sevorix

# Expose the default port
EXPOSE 8080

# Set default environment variables
ENV PORT=8080

# Run the binary
CMD ["sevorix-hub"]
