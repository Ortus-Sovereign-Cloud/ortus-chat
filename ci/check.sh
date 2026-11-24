#!/usr/bin/env bash
# Every check CI runs, in the same order. Run it before each push.
# Storage and file tests also need PostgreSQL and S3 (ORTUS_TEST_POSTGRES,
# ORTUS_TEST_S3_*); CI requires them.
set -euo pipefail
cd "$(dirname "$0")/.."
ci/fetch.sh
# The web client: type-checked against the pinned core's kit, then built
# into web/dist, which the crate embeds. Logical CSS only (right to left
# works), and no style attributes (the CSP forbids them).
if grep -nE '(margin|padding|border)-(left|right)|^[[:space:]]+(left|right):|text-align: *(left|right)|float: *(left|right)|[[:space:]]style=' web/src/*.ts; then
  echo "physical CSS or a style attribute in web/src" >&2
  exit 1
fi
(cd web && npm ci --silent && npm audit --omit=dev --audit-level=moderate && npx tsc --noEmit && npm run build --silent)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
ci/licence-gate-selftest.sh
# The phones' end-to-end crate (its own workspace: see phones/e2e/Cargo.toml),
# tested against the chat app (examples/e2e_host.rs) and the browser's
# e2e.ts. Its licence check fails until the owner rules on MPL-2.0
# (matrix-sdk-crypto's own dependencies and UniFFI) and on RUSTSEC-2026-0459
# (the SQLite matrix-sdk-sqlite 0.19 bundles): docs/phones-end-to-end.md.
(cd phones/e2e && cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --locked -p ortus-e2e)
cargo deny --manifest-path phones/e2e/Cargo.toml check
# The screens in a real browser, against the core with this app.
cargo build --examples
(cd web && npx playwright test)
echo "all checks passed"
