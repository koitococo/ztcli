set dotenv-load
ROOT_PATH := justfile_directory()

fmt-check:
  cargo fmt --all -- --check

clippy:
  cargo clippy --all-targets --all-features -- -D warnings

test:
  cargo test --all-targets --all-features

ci: fmt-check clippy test build

fix:
  cargo clippy --fix --all-targets --all-features --allow-dirty --broken-code
  cargo fmt --all
