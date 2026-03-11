# Use the official Rust image as a builder
FROM rust:1.85-slim-bookworm as builder

# Set the working directory
WORKDIR /usr/src/sevorix

# Install build dependencies for OpenSSL (reqwest)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy the source code
COPY . .

# Build the release binary
RUN cargo build --release

# Use a minimal runtime image
FROM debian:bookworm-slim

# Set the working directory inside the container
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the built binary as 'sevorix' to PATH
COPY --from=builder /usr/src/sevorix/target/release/sevorix_watchtower /usr/local/bin/sevorix

# Copy configuration (no static folder needed as it's embedded)
COPY policies.json /app/policies.json

# Expose port 3000
EXPOSE 3000

# Set the entrypoint
CMD ["sevorix", "run"]
