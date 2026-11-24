# ortus-chat

Ortus chat: rooms and messages, compatible with Matrix federation.

Part of Ortus, a sovereign workspace for organisations and governments: mail, calendar, files, documents, chat, calls, tasks and approvals that an organisation runs itself.

Status: early development, not ready for use.

## Development

This crate depends on `ortus-core` only, at the commit in `pins.toml`. `ci/fetch.sh` checks that commit out under `.deps/`; `ci/check.sh` runs every check CI runs. Programs that include these apps are built in the `ortus` repository.

## Licence

Licensed under either of the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your option.

Dependencies are permissive only (`deny.toml`), with one exception: 2026-11-25: the owner allows MPL-2.0 for unmodified dependencies of the phone encryption library (phones/e2e) only; the server stays Apache/MIT. The crates are named in `deny.toml` and [docs/phones-end-to-end.md](docs/phones-end-to-end.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.
