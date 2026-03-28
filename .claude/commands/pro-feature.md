# Adding a New Pro-Only Feature

This guide documents the pattern for adding a feature that should only be included in the pro build of Sevorix Watchtower. Follow these steps exactly so that lite builds remain unaffected.

---

## 1. Feature declaration in Cargo.toml

The `pro` feature is declared in the **root `Cargo.toml`** (not in individual crates unless they also need to gate code):

```toml
[features]
default = []
pro = []
```

If a workspace crate (e.g. `sevorix-core`) needs to gate code on the pro feature, add the same declaration to that crate's `Cargo.toml` and forward the feature from the root if necessary:

```toml
# root Cargo.toml
pro = ["sevorix-core/pro"]

# sevorix-core/Cargo.toml
[features]
pro = []
```

---

## 2. Gating a new module

In `src/lib.rs`, declare the module with the cfg attribute immediately above it:

```rust
#[cfg(feature = "pro")]
pub mod mymodule;
```

The corresponding file `src/mymodule.rs` (or `src/mymodule/mod.rs`) must exist when the pro feature is enabled, but it will be completely absent from lite builds. Create at minimum a stub file so `cargo build --release --features pro` compiles.

For imports from the module, gate them the same way:

```rust
#[cfg(feature = "pro")]
use mymodule::MyType;
```

---

## 3. Gating AppState fields

Non-pro builds must not include pro fields at all — do not use `Option<T>` as a workaround, since that leaks the type into the lite binary.

Gate fields directly on the struct:

```rust
#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<String>,
    #[cfg(feature = "pro")]
    pub my_pro_field: Arc<RwLock<MyProType>>,
    // ... other fields
}
```

When constructing `AppState`, provide the field only in the pro build:

```rust
let state = AppState {
    tx,
    #[cfg(feature = "pro")]
    my_pro_field: Arc::new(RwLock::new(MyProType::default())),
    // ... other fields
};
```

Both construction paths remain in the same source file — the cfg attributes handle exclusion at compile time.

---

## 4. Gating route registration in build_router()

Wrap pro-only `.route(...)` calls in a cfg block inside `build_router()` (in `src/lib.rs`):

```rust
let router = Router::new()
    .route("/analyze", post(analyze_handler))
    .route("/proxy", get(proxy_handler));

#[cfg(feature = "pro")]
let router = router
    .route("/receipts", post(receipt_handler))
    .route("/receipts/:id", get(get_receipt_handler));

router
```

---

## 5. Gating CLI arms

**In `src/cli.rs`**, add the variant with a cfg attribute:

```rust
#[derive(Subcommand)]
pub enum Commands {
    // existing variants ...

    #[cfg(feature = "pro")]
    /// Pro-only command
    MyProCommand {
        #[arg(short, long)]
        some_arg: String,
    },
}
```

**In `src/main.rs`**, gate the match arm the same way:

```rust
match command {
    // existing arms ...

    #[cfg(feature = "pro")]
    Commands::MyProCommand { some_arg } => {
        mymodule::run(some_arg).await?;
    }
}
```

---

## 6. Verification

Always verify both build targets compile before committing:

```bash
# Lite build (no pro features)
cargo build --release

# Pro build
cargo build --release --features pro
```

Both must compile without errors or warnings (run `cargo clippy` for the full check).

---

## 7. Lite strip process note

The publish-lite CI workflow strips lines matching `#[cfg(not(feature = "pro"))]` from the source before publishing. Pro-gated code uses `#[cfg(feature = "pro")]`, which means it is simply **absent** from lite builds — the strip script does not need to touch it. Never use `#[cfg(not(feature = "pro"))]` to guard pro-only code; that attribute is reserved for code that should exist in lite but be excluded from pro (an unusual case).

In summary:
- `#[cfg(feature = "pro")]` — present only in pro builds, ignored by the strip script
- `#[cfg(not(feature = "pro"))]` — present only in lite builds, **removed by the strip script**
