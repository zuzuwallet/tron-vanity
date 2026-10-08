# tron-vanity

Offline generator for one TRON mainnet account address whose Base58Check text starts with a chosen prefix.

## `TZuZu` cannot occur

`tron-vanity generate TZuZu` does not search, and it does not substitute another prefix. It exits with an error and writes no wallet.

A mainnet account address is the Base58Check encoding of a 25-byte payload whose first byte is `0x41`. Every such payload is an integer in `[0x41 << 192, 0x42 << 192)`. Both ends encode to 34 characters:

```text
T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR
TZJozAg1ruapycCicgz31GxvYJ1FvTVysk
```

Those two strings are the encoding endpoints of the version byte. They are not claimed as funded accounts. `TZuZu` sorts after the high endpoint. A prefix that begins with `TZ` only continues through `TZJozA`. `TZZ` and `TZK` fail for the same reason.

The leading `T` is imposed by that encoding. The characters this tool can still choose, for an interior prefix, start at the second character. A same-difficulty illustration is `THZZZ`: four vanity characters, `HZZZ`. Under the model below, the expected attempt count is 4,553,521 and the 50% point is 3,156,260. The coarser `58^4 = 11,316,496` is an approximation of unconstrained Base58 characters. It is not the search number.

```bash
tron-vanity generate THZZZ
```

A `T...` string from this program is a normal public account address. Vanity does not make the address private. An account is not active on TRON until it is created on chain, which this program does not do. This program also does not check whether anyone has already used the address.

Passing `cargo test` does not make a wallet appropriate for significant funds. Review the derivation, the wallet format, and the compiled binary yourself, or have someone else review them, before you send value to an address it produced. A green test run shows that this program matched the vectors and checks named below.

Never paste a generated private key, the encryption passphrase, or the wallet file into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret. Only the public `T` address may be shared.

The 20-byte account id is the Ethereum address of the same public key. Do not import an exported TRON private key into Ethereum or any other EVM wallet. That scalar would control the TRON account and the EVM address together.

The compiled generator does not open network connections. It has no RPC client, block explorer client, telemetry, update check, or HTTP client. Generation and verification work without a network. `reqwest` is not in the resolved graph (`cargo tree -i reqwest` reports no such package). The release binary's dynamic symbol table, checked with `nm -u`, has no `connect`, `getaddrinfo`, or `sendto`.

## What it does

For each candidate the program:

1. Reads exactly 32 bytes from the operating-system CSPRNG (`getrandom`, one call per candidate).
2. Accepts those bytes only when they are a secp256k1 scalar in `1..=n-1`. Zero and values at or above the curve order are discarded and are not counted as attempts. The bytes are not reduced modulo `n`.
3. Derives the uncompressed SEC1 public key with libsecp256k1 (`0x04` plus the 32-byte X coordinate and the 32-byte Y coordinate).
4. Drops the `0x04` byte and computes Keccak-256 of the remaining 64 bytes. NIST SHA3-256 is a different function and is not used for the address.
5. Takes the last 20 bytes of that digest. In Rust that is `hash[12..32]`.
6. Builds the 25-byte payload `[0x41] || those 20 bytes || checksum`, where the checksum is the first 4 bytes of SHA-256(SHA-256(of the 21-byte body)).
7. Compares that payload with the inclusive bounds of the requested prefix. Base58 text is built only when the payload is inside the bounds, and the text must still start with the prefix.

The first match is checked again through `k256`, `sha3::Keccak256`, `bitcoin_hashes`, and `bs58` before it is treated as found. That check runs before any wallet file is created. The 32-byte scalar is then encrypted and written to a new file created with mode `0600`. The private key is not printed. `export` is the only command that prints it, and it asks you to type `EXPORT` first.

There is no HD path and no mnemonic. General TRON wallets use BIP-44 path `m/44'/195'/0'/0/index`. This tool generates one standalone random key. It does not sign transactions and it does not build them.

The address prefix byte `0x41` is what the current Developer Hub documents for mainnet and for the Shasta and Nile test networks. This wallet file is labeled `mainnet`. The legacy prefix `0xa0` is unused and is not generated. Contract addresses and the SM2 curve are out of scope.

## Fedora: build online, then disconnect

Install a C compiler and Rust while the machine can reach the network. `secp256k1` compiles C code through `cc`. Python is required for the PTY test.

```bash
sudo dnf install gcc python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny
```

The checks recorded in this file used rustc 1.99.0 (`b940084d7`, 2026-09-28) and cargo 1.99.0 (`5f94df478`, 2026-08-27). On a machine where `sudo` is unavailable, a user-local GCC works if `CC`, `AR`, `C_INCLUDE_PATH`, and `LIBRARY_PATH` point at that toolchain. A GCC configured with `--prefix=/usr` and then unpacked somewhere else does not search its own `usr/include` unless `C_INCLUDE_PATH` is set. That is an environment workaround, not the normal Fedora install. A benchmark run that forgot `CC` failed inside `secp256k1-sys` with `failed to find tool "cc"`.

From this directory, while still online:

```bash
umask 077
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
cargo deny check advisories bans licenses sources
cargo build --release
```

Read `Cargo.toml`, `Cargo.lock`, and the source before you trust the binary. The versions below are the ones resolved for this tree. `cargo audit` and `cargo deny` download advisory data. The `tron-vanity` binary does not.

Then disconnect and use only the binary you just built:

```bash
nmcli networking off
./target/release/tron-vanity self-test
./target/release/tron-vanity generate THZZZ
./target/release/tron-vanity verify THZZZ-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step. Restore networking later with `nmcli networking on` only after the encrypted file is on the media you intend to keep. `TZuZu`, `ZuZu`, and `T0` fail before a search and do not write a wallet. `self-test` was run here on the release binary and printed `Cryptographic self-tests: PASS`. A network namespace (`unshare -n`) was not permitted in this environment, and host networking was not switched off. The symbol check above is what was available instead.

Copy the wallet file to offline storage. The file mode is `0600` from the moment it is created. Keep the passphrase with the same care as the file. Set `umask 077` in the shell that runs `generate`. Put the wallet in a directory you create with `mkdir -m 700`. Only after the encrypted secret is backed up, and after a separate review of how you will spend from it, consider funding the address.

## Commands

```bash
tron-vanity self-test
tron-vanity generate THZZZ
tron-vanity generate THZZZ --threads 16
tron-vanity generate THZZZ --threads 16 --output THZZZ-wallet.json
tron-vanity verify THZZZ-wallet.json
tron-vanity export THZZZ-wallet.json
```

`generate` defaults to `std::thread::available_parallelism`, clamped to 1..=256. `--threads 0` and values above 256 are rejected. The default output path is `{prefix}-wallet.json`. An existing output file is refused. There is no overwrite flag. Pick a different `--output` path. The parent directory must already exist. Both checks happen before the search starts. If that directory is writable by group or others, `generate` prints a warning and continues. Create it with `mkdir -m 700`. Mode `0600` on the wallet does not stop someone who can write the directory from unlinking or replacing the file after the public address is printed.

There is no `--password` flag. The passphrase is read from the terminal with echo off. A new wallet rejects a passphrase shorter than 12 Unicode scalar values or longer than 1024 bytes. The value is not trimmed. `verify` and `export` still open a shorter passphrase so an older file is not stranded. The 12-scalar check only stops accidents. It is not a measure of guessing resistance.

Before the search, and after the self-test, `generate` prints the target, the vanity portion, the approximate difficulty, the attempt count at which the model gives about a 50% chance of a hit, and the labeled `58^N` approximation. For `THZZZ` that text is:

```text
Target: THZZZ
Vanity portion: HZZZ
Difficulty: approximately 4,553,521
50% probability after approximately 3,156,260
Per-character approximation: 58^4 = 11,316,496
There is no guaranteed completion time.
```

`T` prints vanity portion `(none)`, difficulty 1, and `58^0 = 1`. The search is probabilistic. The counter can stop, the process can be cancelled, and the machine can be slower than any average. A prefix whose estimate is at least one billion attempts asks you to type `SEARCH` before workers start. That prompt is installed before the Ctrl-C handler. `THZZZ` does not ask.

Ctrl-C sets an atomic flag. It does not call `process::exit`. Workers leave the candidate loop on that flag. A hit that races with Ctrl-C is discarded. If Ctrl-C arrives while the passphrase prompt is up, echo is restored and no address or private key is printed. `export` checks the flag again after the hex key is encoded and before it is printed.

`generate` prints `FOUND` and the public address only after the wallet file has been linked into place and the parent directory has been synced. On a write error it prints `Wallet was not saved successfully.` and does not print the address. A passphrase failure prints `Wallet was not saved.` The raw key and the passphrase are dropped before the success lines. `verify` drops them before the `PASS` lines. `export` drops the passphrase after decryption and the raw key after hex encoding, then checks the interrupt flag again, then prints `Private key:`.

`verify` reports only public information:

```text
Wallet authentication: PASS
Private key validity: PASS
Address derivation: PASS

Stored:
T...

Derived:
T...

MATCH: YES
```

`export` requires both stdin and stdout to be terminals. It prints a warning, waits for the line `EXPORT`, then the passphrase. The printed secret is 64 lowercase hexadecimal characters with no `0x` prefix. It is not a Bitcoin WIF. Clear the scrollback after you have copied it onto offline media.

## Derivation

Authoritative pages, read for this tree:

- TRON Developer Hub, Account: <https://developers.tron.network/docs/account>. A private key is 32 random bytes. The account identifier is the last 20 bytes of Keccak-256 of the public key, and those 20 bytes are the Ethereum address of the same public key. The on-chain address form prepends `0x41`. The page was current when this crate was written (about three weeks before 2026-10-08).
- TRON Developer Hub, Encoding: <https://developers.tron.network/docs/encoding>. Base58Check is the 21-byte address (`0x41` plus 20 bytes) plus the first 4 bytes of SHA-256(SHA-256(of that 21-byte string)), then Base58 of the 25 bytes. The page states that `0x41` is the address prefix on all current networks, and that the legacy byte `0xa0` is unused. The visible address is 34 characters and starts with `T`.
- TronWeb 5.2.0 `createAccount` example: <https://tronweb.network/docu/docs/5.2.0/API%20List/utils/createAccount>. The page publishes an uncompressed public key, a 20-byte identifier, and a Base58 address. The scalar on that page is redacted. This crate does not reconstruct it.

The English account page says Keccak-256 of the public key and also says the 20-byte result matches the Ethereum address of that key. Ethereum hashes the 64-byte `X||Y` and drops the SEC1 `0x04` prefix before the hash. This crate does the same. A test fails if the 65-byte form is hashed. A test fails if SHA3-256 is used in place of Keccak-256. A test fails if `hash[11..31]` is used in place of the last 20 bytes.

java-tron's historical `sha3omit12` copies Keccak bytes starting at index 11 and then overwrites the first copied byte with `0x41`, which leaves `hash[12..32]`. That matches "last 20 bytes, then prepend `0x41`". The raw `Hash.java` URL checked during this work returned 404, and java-tron was not built or run. The behavior above is what the Developer Hub sentences require, and what both Rust stacks implement.

Keccak-256 uses sponge domain byte `0x01`. NIST SHA3-256 uses domain byte `0x06`. `tiny-keccak` is built with the `keccak` feature only. The `sha3` crate's `Sha3_256` is present so the negative test has a real SHA3 implementation. Empty-string outputs, which the self-test locks:

| Hash | Empty string |
| --- | --- |
| Keccak-256 | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| SHA3-256 | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` |

Keccak-256 of `abc` is `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45`.

The Base58 alphabet is `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. It excludes `0`, `O`, `I`, and lowercase `l`.

Curve order `n` is `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.

### Why `58^4` is the wrong estimate for `THZZZ`

Four unconstrained Base58 characters would be `58^4 = 11,316,496`. That model pretends every character after `T` is uniform over the whole alphabet. The second character is not. Only these 25 symbols occur there:

```text
9ABCDEFGHJKLMNPQRSTUVWXYZ
```

`9` and `Z` are partial buckets at the ends of the version interval. Interior second characters `A` through `Y` sit fully inside it. No lowercase letter is a legal second character. `Tz` is rejected because `z` is not in that set, before any rarity check. `T0` is rejected earlier, as an alphabet error, because `0` is not Base58.

Under the model used here, every 25-byte payload that starts with `0x41` is equally likely, which is the same as treating the 20-byte account id as uniform and the checksum as an independent 32-bit field. `THZZZ` covers `58^29` of those payloads. The expected number of attempts is the nearest integer of `2^192 / 58^29`, which is 4,553,521. The 50% figure is `round(4,553,521 * ln 2) = 3,156,260`. `58^4` is about 2.5 times too high for this prefix. The program prints both, and it labels the power of 58 as an approximation.

This is a model of the encoding, not a proof that Keccak-256 outputs are uniform. The checksum is part of the 25-byte value the search compares. For a short interior prefix the checksum cannot move the text out of the prefix, because the prefix bucket is far wider than 2^32. The comparison still includes it so a long or edge prefix stays exact. `T9` and `TZ` use the intersected integer count. Their expected attempt counts are not 23, which is the count for an interior length-2 prefix such as `TH`.

Other locked counts: `T` is 1, `TH` is 23, `THZ` is 1,354, `THZZ` is 78,509. An interior 12-character prefix such as `THVVVVVVVVVV` has expected count `10,054,102,514,374,869,639` and asks for `SEARCH` because that is at least one billion. Thirteen constrained characters do not fit in the `u64` attempt counter with 1,048,576 attempts of headroom, and the command rejects them before searching. A full 34-character string with a valid `0x41` checksum is one key out of 2^160 and is rejected for the same counter reason. A full 34-character string with a bad checksum is rejected as impossible.

The in-search counter stops 1,048,576 attempts before a `u64` would wrap. A prefix is accepted when its expected count fits under that stop. That is not a promise the search will hit before the stop. `THVVVVVVVVVV` is accepted and asks for `SEARCH`. Its expected count is about 1.005×10^19, and the counter stops near 1.845×10^19, about 1.83 times the mean. Under the geometric model, the chance of reaching that stop with no match is about 16%. The command then returns `search failed` and writes no wallet. That prefix is not a practical search. The cap was not tightened further, because doing so would reject this same prefix.

### Known answers

Self-test compares whole address strings and whole public keys. A failure aborts before any search or wallet write. `address.starts_with("T")` is not the test.

| Check | Value | Source |
| --- | --- | --- |
| SHA-256 of the empty string | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | FIPS 180-4. `bitcoin_hashes` is locked to this constant in the self-test. `sha2` is locked to the same constant in `src/tron/hash.rs`. The two outputs are not compared with each other |
| Keccak-256 of the empty string | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` | Keccak test vector. Differs from SHA3-256 |
| SHA3-256 of the empty string | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` | NIST SHA3. Negative check |
| Keccak-256 of `abc` | `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45` | Keccak test vector |
| Private key 1, uncompressed | `0479be667e…f81798` followed by `483ada77…10d4b8` | SEC 1 generator. The full 65-byte point is locked in `src/self_test.rs` |
| Account id of private key 1 | `7e5f4552091a69125d5dfcb7b8c2659029395bdf` | Ethereum address of that public key, which the Developer Hub identifies with the TRON account id |
| Address of private key 1 | `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC` | protocol rules, agreed by libsecp256k1 / tiny-keccak / `sha2` and by `k256` / `sha3::Keccak256` / `bitcoin_hashes` / `bs58`. Not a line java-tron printed |
| Last 20 bytes if the `0x04` byte is hashed | `7d6e99bb8abf8cc013bb0e912d0b176596fe7b88` | negative check. Must not equal the account id |
| Last 20 bytes of SHA3-256 of the 64-byte key | `0502987e630ea7ebb2bf1d84a65a727109385bcf` | negative check. Must not equal the account id |
| TronWeb published public key | `04FFFA899E…A0C1` (130 hex characters, in `src/self_test.rs`) | TronWeb `createAccount` docs, 2026-09-20. The scalar is redacted and is not in this repository |
| TronWeb account id | `edc66496a39744fea631a598cbae4b7d6a728aa7` | the same page |
| TronWeb address | `TXeSp72o5r185cmeGxFDkdCZFdJS1TAyHw` | the same page. Hex form `41EDC66496A39744FEA631A598CBAE4B7D6A728AA7` |
| Docs encoding pair | `418840E6C55B9ADA326D211D818C34A994AECED808` ↔ `TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL` | the classic published pair. The current account page truncates it. Both encoders in this crate agree |

Private key 1 is the public SEC 1 generator scalar, the integer 1. It is a test input. It is not a wallet this program generated, and the program does not print it as an export.

The USDT contract address `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` is a contract, not an account-key vector, and it is not used.

### Independent check

The search stack is libsecp256k1 0.30.0 (via `secp256k1-sys` 0.10.1), `tiny-keccak` 2.0.2, `sha2` 0.10.9, and this crate's Base58Check. The check that must agree uses different code:

- `k256` 0.13.4 for the uncompressed public key
- `sha3` 0.10.9 `Keccak256` for the 64-byte hash and the last 20 bytes
- `bitcoin_hashes` 0.16 for the double SHA-256 checksum
- `bs58` 0.5.1 for the Base58 alphabet only. Its `check` feature is off, so it does not call `sha2`

`confirm_match` compares the 65-byte public key, the 20-byte account id, and both address strings. It does not call this crate's address encoder twice and call that independence. A mismatch returns `FATAL ERROR — DO NOT USE THE WALLET`, prints no key, and does not create a wallet file. The CLI runs that check again before it asks for a passphrase. The check is local. It does not contact a node.

java-tron and TronWeb were not executed. Two Rust libraries can share a wrong reading of the same English page. That limit is why the TronWeb published public key and the docs hex pair are locked as well: those strings were printed by TRON's own documentation, and this crate only accepts them when its own encoder reproduces them.

### Private-key serialization

The export format is 64 lowercase hexadecimal characters, no `0x` prefix. Uppercase hex and a `0x` prefix are rejected on import. The wallet stores the raw 32-byte scalar, not the hex text. `export` prints one line, `Private key:`, followed by that hex. Importing it and deriving the address again must produce the stored `T` address. `verify` does that derivation and does not print the key.

## Prefix estimate

Rejected prefixes name the reason:

| Prefix | Reason |
| --- | --- |
| empty | prefix is empty |
| `ZuZu`, `tZuZu` | mainnet account addresses start with `T` |
| `T0`, and any `0`, `O`, `I`, or `l` | character outside Base58. Checked before the leading-`T` rule, so `T0` is an alphabet error |
| `Tz` | the second character can only be `9ABCDEFGHJKLMNPQRSTUVWXYZ` |
| `TZuZu`, `TZZ`, `TZK` | outside the `0x41` integer range. `TZ` only continues through `TZJozA` |
| longer than 34 characters | longer than an account address |
| 13 or more constrained characters, when the estimate does not fit | too rare for the attempt counter |
| a full valid 34-character address | one key out of 2^160 |

`TZJ` is inside the range and is accepted when the rest of the length rules pass.

## Secret storage

The wallet file holds ciphertext of the 32 raw scalar bytes. It does not hold hex text. Ciphertext length is 48 bytes: 32 bytes of key plus a 16-byte Poly1305 tag. Format version 1 accepts only the production KDF. `open_and_verify` returns a format error before Argon2 runs when the file asks for any other parameters, including the cheap parameters used by unit tests. The binary has no flag that selects a weaker KDF. In-crate tests use a private writer with a small Argon2 setup (32 KiB, 1 iteration, parallelism 1) and still reject parameters outside fixed caps: memory at most 1,048,576 KiB, iterations 1..=100, parallelism 1..=16, and at least 8 KiB per lane.

- KDF: Argon2id, version 19 (`0x13`), memory 65536 KiB, 3 iterations, parallelism 4, 16-byte salt, 32-byte output. This is RFC 9106 section 4, second recommended option. The caller owns the Argon2 block memory as a `Zeroizing` boxed slice (`hash_password_into_with_memory`).
- AEAD: ChaCha20-Poly1305. The nonce is 12 bytes from the OS CSPRNG.
- Associated data is `tron-vanity-wallet-v1`, a NUL, the public address, then `\0account\0uncompressed\0mainnet`. Changing the stored address, address type, public-key encoding, or network label fails authentication.

The JSON object uses `deny_unknown_fields` and a trailing newline. Fields:

```text
format_version: 1
network: "mainnet"
address_type: "account"
public_address: "T..."
public_key_encoding: "uncompressed"
address_prefix: "41"
kdf: "argon2id"
kdf_parameters: { version: 19, memory_kib, iterations, parallelism }
salt: base64, 16 bytes
cipher: "chacha20poly1305"
nonce: base64, 12 bytes
ciphertext: base64, 48 bytes
```

The salt is a top-level field. It is not repeated inside `kdf_parameters`. The public address stays in plaintext. Files larger than 1 MiB are rejected.

`confirm_match` runs inside the writer before the ciphertext is written. A mismatch does not create a file. If a mismatch were discovered only after a file already existed, the file would have to be treated as saved and unusable. This writer does not take that path.

The file is created as a temporary name in the same directory with `O_CREAT|O_EXCL` and mode `0600`. If the created mode has any group or other permission bits, the write fails and the temporary file is removed. The temp file is `fsync`ed and then hard-linked onto the destination. The link fails if the destination already exists, including when the name appears while Argon2 is running. The public writer also refuses an existing path before Argon2 starts. The temp name is removed afterward. The parent directory is `fsync`ed. If that sync fails, the wallet file is left in place, the command returns an error, and the address is not printed. Run `verify` on the file to read the public address.

Create that directory with `mkdir -m 700`. A wallet mode of `0600` does not stop another user who can write the parent directory from removing or replacing the file after `generate` has printed the public address. The command warns when the parent is group- or world-writable (`mode & 0o022 != 0`). It does not refuse the directory, because some shared filesystems use those modes on purpose. That warning is taken before the search and is not repeated when the file is published. It is a hint for a single-user machine, not a defense against someone who changes the parent directory during a long run.

A read opens the path once with the Linux `O_NOFOLLOW` flag (`0x20000`) and takes the size and the bytes from that file descriptor. A symbolic link is rejected. `ELOOP` is errno 40. That flag is Linux-specific. This program targets Fedora. `O_NOFOLLOW` is passed through `OpenOptions::custom_flags`.

Decrypting a production wallet uses about 64 MiB of RAM for a few iterations. Plan for that on the machine that runs `verify` or `export`.

### Zeroization

`SecretBytes` and `SecretString` wrap the `zeroize` crate. `Debug` prints `[redacted]`. The Argon2 output and the AEAD key are `Zeroizing`. The Argon2 working memory, about 64 MiB for a production wallet, is a `Zeroizing` boxed slice of blocks passed into `hash_password_into_with_memory`. `argon2` is built with its `zeroize` feature. Direct `generic-array` 0.14.7 is pinned with the `zeroize` feature because argon2 0.5.3 calls `GenericArray::zeroize` without enabling that feature itself.

Hex encode keeps the secret in `SecretString` until the caller drops it. Base58 encode and decode of secret material keep their working bytes in `Zeroizing` buffers. Public address text is an ordinary `String`. `verify` drops the decrypted key before it prints the public address. `export` drops the passphrase after decryption and the raw key after hex encoding. The hex string stays until the `Private key:` line. `generate` drops the passphrase and the raw key after the wallet is saved, before it prints the public address.

That is best-effort on a general-purpose Fedora workstation. It does not cover:

- copies the allocator, the compiler, or registers already made
- swap, hibernation, and crash dumps
- compiler copies, registers, and copies inside libsecp256k1 public-key generation. `SecretKey` is `Copy`. A private guard borrows that one value and calls `non_secure_erase` on drop, which overwrites it with libsecp256k1's erase pattern (`[1u8; 32]`), not with zeros. The guard does not construct a second `SecretKey`
- compiler, register, and temporary copies around `k256::SecretKey`. That type zeroizes its scalar on drop. `k256` 0.13 has no `zeroize` Cargo feature. The type is not `Copy`, and the independent check calls `drop` after the public bytes are copied
- the per-lane address and input blocks `argon2` keeps on its own stack during key derivation
- terminal scrollback after `export`
- a process killed with `SIGKILL`, which does not run destructors

The program does not install a process-wide panic hook. Error text does not include a key, hex secret, passphrase, or ciphertext. Disable crash dumps and swap, or encrypt swap, on a machine that will hold a key in memory. `export` is the operation that deliberately puts the hex key on the screen.

## Threat model and limitations

Assumed: the OS CSPRNG, the CPU, and the machine you build and run on are not already hostile. These break the program, and tests do not detect them:

- a compromised Fedora installation, including malware and a keylogger
- a compromised Rust compiler or toolchain
- a malicious Cargo dependency or other supply-chain substitution
- an OS CSPRNG that returns predictable bytes
- memory scraping, swap, and core dumps
- plaintext copies of the key outside this process, including a backup of the wallet file together with the passphrase, and a terminal log or scrollback of `export`
- a weak encryption passphrase, including one that passes the 12-character check
- an implementation error, including hashing the `0x04` byte, using SHA3-256, or taking the wrong 20 bytes
- a verifier that is not actually independent of the generator
- fake wallet software that asks you to type or upload the key this program printed

In scope, and what the tests are aimed at: the uncompressed public key, dropping `0x04`, Keccak-256 rather than SHA3-256, the last 20 bytes, the `0x41` prefix, Base58Check, a key that does not match the stored address, a wallet file left world-readable, a passphrase on the command line, a search that continues after the first hit, and a damaged or substituted ciphertext.

Out of scope, and not solved here: malware on the host, someone reading the terminal during `export`, physical access, side channels, and bugs inside libsecp256k1, `k256`, `sha3`, `bitcoin_hashes`, `bs58`, `argon2`, or `chacha20poly1305`. Each libsecp256k1 context is randomized once from `getrandom` before public-key generation. That is the library's recommended hardening for secret-key operations. The context is not re-seeded on every candidate, and it is not re-randomized on a timer. Periodic re-randomization was considered and left out, because side channels stay out of scope.

Further limits:

- The tool never asks the network if the address is already in use. This program does not check.
- There is no signing path and no HD path. Spending from the address still needs a separate, reviewed wallet. A normal TRON wallet expects `m/44'/195'/0'/0/index`, which this file is not.
- Do not reuse the exported scalar on Ethereum or another EVM chain. The 20-byte id is that chain's address for the same key.
- Successful tests do not make this software appropriate for storing significant funds.
- Workers stop on the first match. Another worker can have drawn a key it then discards. That buffer is zeroized when the `Zeroizing` value drops. A killed process does not run that drop.
- If any worker panics or the RNG fails, a match from another worker is discarded and no wallet is written. A context-seed failure while opening a wallet is an RNG error. It is not reported as "do not use the wallet."
- A hit that races with Ctrl-C is discarded.
- Attempt counters stop with an error before a `u64` would wrap.
- `generate` and `write_encrypted_wallet` reject a new passphrase shorter than 12 Unicode scalar values. Argon2id does not rescue a guessable passphrase.
- Public wallet reads and writes accept only the production Argon2 parameters.
- Workers do not split the key space. Each draw is a fresh 32-byte OS read. There is no counter used as a key and no per-worker seed. Invalid scalars are not counted as attempts.
- Each worker builds one libsecp256k1 context. The hot path does not take a lock per candidate. The stop flag is atomic. Progress is printed about once a second. The thread name is `tron-vanity`. The candidate chunk size is 1024.

## What was not independently verified

- java-tron and TronWeb were not built or run. The `Hash.java` raw URL returned 404. The derivation follows the Developer Hub account and encoding pages, plus the published TronWeb public key and address.
- `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC` was not printed by an official TRON tool. The 20-byte id is the published Ethereum address of private key 1. Both Rust stacks agree, and the tests lock that Base58 string.
- The TronWeb example address was published, but the scalar on that page is redacted (`D9AA****1A7E` in the current docs). This repository does not contain a reconstructed scalar, so the scalar-to-public-key step of that example is not locked. The published uncompressed public key is locked.
- The difficulty figure is a model. It is not a proof that Keccak-256 is uniform, and it is not a completion-time guarantee.
- No live multi-million-attempt search was run, and no generated wallet was funded. Tests search only short prefixes (`T`, and cancellation of a longer prefix).
- `nmcli networking off` was not run. `unshare -n` returned `Operation not permitted` in an earlier session on this host and was not retried.
- `perf` is not installed, so there is no sampled profile. The miss path in this crate does not call Base58 and does not build an address `String`. That does not prove libsecp256k1 avoids internal allocation.
- `cargo-geiger` was not installed. This crate forbids `unsafe` in its own code. Dependencies still contain `unsafe`.
- Side channels are not solved. Context randomization is one-time defense in depth.
- Zeroization on a normal desktop OS does not cover allocator copies, swap, crash dumps, registers, or `SIGKILL`.

## Benchmarks

Correctness is the constraint. The hot loop was measured after the known-answer tests passed. A miss is one `getrandom` of 32 bytes, one libsecp256k1 uncompressed public key, Keccak-256, the 4-byte checksum, and a 25-byte compare. Base58 runs only after the payload is inside the prefix bounds.

The fixed key in `miss_without_base58` is the secp256k1 generator (private key 1). Its address does not start with `THZZZ`, so the compare takes the miss path. The bench does not print that address or the scalar. `getrandom_and_miss` draws a fresh key each iteration and zeroizes the buffer.

Two Criterion runs on this 16-thread machine, each with 50 samples, 1 second of warmup, and 3 seconds of measurement. The source did not change between them. Criterion compared the second run with the first and reported an improvement. Treat that as run-to-run variance, not as a tuned result.

| Bench | First run | Second run |
| --- | --- | --- |
| `miss_without_base58` | 22.945 µs (22.743–23.148), 1 high mild outlier | 20.432 µs (20.287–20.570), 3 high severe outliers |
| `getrandom_and_miss` | 22.003 µs (21.840–22.191), 1 high mild outlier | 20.600 µs (20.337–20.880), 1 high mild outlier |

At about 20–23 µs, one core is on the order of 43,000 to 50,000 candidates per second in these two samples. Do not treat either row as the machine's capacity, and do not multiply by 16. Multi-thread throughput was not measured. `getrandom` can contend, and the machine can be busy. `THZZZ` expects about 4,553,521 attempts under the model above. There is no promised completion time.

An earlier repeat failed before any sample because `CC` was unset and `secp256k1-sys` could not find `cc`. That run is not a timing result.

Repeat the measurement with the same compiler environment you used to build:

```bash
cargo bench --bench derive
```

## Dependency and security review

Direct dependencies, from `cargo tree --depth 1 -e normal` and the resolved `Cargo.lock`:

| Crate | Version | Role |
| --- | --- | --- |
| argon2 | 0.5.3 | Argon2id, `zeroize` feature on. Argon2 0.6 exists and was not taken |
| generic-array | 0.14.7 | Enables `GenericArray::zeroize` for argon2 0.5.3 |
| base64 | 0.22.1 | Wallet encoding |
| bitcoin_hashes | 0.16.0 | Independent double SHA-256. `default-features` off, `std` on. 1.2.0 exists and was not taken |
| bs58 | 0.5.1 | Independent Base58 text. `check` feature off, so this copy does not hash |
| chacha20poly1305 | 0.10.1 | AEAD |
| clap | 4.6.7 | CLI |
| ctrlc | 3.5.2 | Ctrl-C flag |
| getrandom | 0.2.17 | OS CSPRNG. One 32-byte draw per candidate, plus one 32-byte context seed per libsecp256k1 engine, plus salt and nonce |
| k256 | 0.13.4 | Independent secp256k1. Features `arithmetic` and `std` only. No `zeroize` Cargo feature. `SecretKey` still zeroizes its scalar on drop |
| rpassword | 7.5.4 | Passphrase prompt |
| secp256k1 | 0.30.0 | Search-path libsecp256k1. Default features off. `std` and `alloc` only. `rand` is not enabled |
| secp256k1-sys | 0.10.1 | C library behind `secp256k1`. Built with `cc` |
| serde / serde_json | 1.0.229 / 1.0.151 | Wallet JSON |
| sha2 | 0.10.9 | Search-path double SHA-256 checksum |
| sha3 | 0.10.9 | Independent `Keccak256`, and `Sha3_256` for the negative test |
| thiserror | 2.0.21 | Errors |
| tiny-keccak | 2.0.2 | Search-path Keccak-256. Feature `keccak` only |
| zeroize | 1.9.1 | Secret wipe |
| criterion | 0.5.1 | Benchmarks only |

`cargo tree -p secp256k1@0.30.0` shows `secp256k1-sys` and its build dependency `cc`. `Cargo.lock` still records `rand` 0.8.8 and `rand_chacha` 0.3.1 because `secp256k1` 0.30.0 declares `rand` as optional. `cargo tree -i rand` prints nothing. Candidate scalars and the context seed come from `getrandom`. `seeded_randomize` does not need the `rand` feature.

`Cargo.lock` also records `bitcoin_hashes` 0.14.101 as that same unused optional dependency of `secp256k1`. `cargo tree -i bitcoin_hashes@0.14.101` prints nothing. The independent checksum is `bitcoin_hashes` 0.16.0, and `cargo tree -i bitcoin_hashes@0.16.0` shows only this crate. `cargo deny` did not report a duplicate-version finding for the unused 0.14.101 entry. `cargo tree -i sha2` shows only this crate. `cargo tree -p bs58@0.5.1` prints `bs58` alone. The lockfile entry for `bs58` still names `tinyvec`. Its `check` feature is off, so that copy does not call `sha2`.

`blake2` 0.10.6 is pulled in by `argon2`. `reqwest` is absent.

`cargo audit` 0.22.2 loaded 1294 RustSec advisories and scanned 155 crate dependencies. Exit code 0. No vulnerability text was printed.

`cargo deny` 0.20.2 with `deny.toml`: advisories ok, bans ok, licenses ok, sources ok (crates.io only). Exit code 0. It warned that `BSD-1-Clause` and `ISC` are on the allow-list and were not encountered. This lockfile has no crate under those two licenses. The allowance is unused.

The license allow-list is MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause, BSD-1-Clause, ISC, Unicode-3.0, CC0-1.0, Unlicense, and Zlib.

The library, the binary, the integration tests, and the benchmark set `#![forbid(unsafe_code)]`. libsecp256k1, `k256`, and other dependencies contain unsafe code inside their own crates.

Recorded local gates, on the source in this tree:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all` (57 tests: 40 library, 3 binary, 4 CLI, 3 prefix, 1 PTY, 5 search, 1 vectors)
- `cargo audit`
- `cargo deny check`
- `cargo build --release`
- `./target/release/tron-vanity self-test`
- release `generate` of `TZuZu`, `ZuZu`, and `T0`, each with exit code 1 and no wallet file created

## Layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore          /target and *-wallet.json
LICENSE-APACHE
LICENSE-MIT
README.md
src/lib.rs          crate root, no unsafe
src/main.rs         CLI
src/error.rs
src/secret.rs       zeroizing wrappers
src/hexutil.rs
src/self_test.rs    known answers, run before a search
src/independent.rs  k256, sha3::Keccak256, bitcoin_hashes, bs58
src/verify.rs       both stacks must agree
src/search.rs       threads, cancellation, one getrandom per candidate
src/wallet.rs       Argon2id, ChaCha20-Poly1305, and wallet tests
src/tron/base58.rs  Base58Check
src/tron/hash.rs    Keccak-256, double SHA-256, SHA3-256 negative check
src/tron/hexkey.rs  64-character lowercase hex
src/tron/keys.rs    libsecp256k1 uncompressed account payload
src/tron/prefix.rs  version-byte range and the attempt estimate
src/tron/uint.rs    256-bit arithmetic for prefix setup only
tests/vectors.rs
tests/prefix.rs
tests/search.rs
tests/cli.rs
tests/pty_ctrlc.rs
tests/pty_ctrlc.py
benches/derive.rs
```

## Tests

`cargo test --all` covers secp256k1 rejection of zero and of the curve order, the generator uncompressed point, Keccak-256 versus SHA3-256, hashing with and without `0x04`, the last-20-byte cut versus `hash[11..31]`, the `0x41` prefix, the Base58 alphabet, Base58Check, the private-key-1 address, the TronWeb published public key and address, the docs hex pair, prefix rejection including `TZuZu`, the `THZZZ` estimate, multithreaded cancellation, a `T` search that stops every worker, encrypted round trip, mode `0600`, wrong passphrase, tampered ciphertext, tampered address, truncated JSON, unknown fields, hostile KDF parameters, non-production KDF rejection, symlink rejection (`ELOOP`), overwrite refusal, hex import back to the same address, and an independent-check mismatch. One test runs `python3` on a PTY: Ctrl-C at the passphrase prompt must restore echo and cancel, and `generate` must not print `FOUND`, `Address:`, or `Private key:` before a wallet exists. The same test plants a file at the output path during the passphrase prompt and checks that the command fails with `Wallet was not saved successfully.` That test fails if `python3` is not installed. The passphrase in that test is a fixture, not a secret to reuse.

Integration tests use `CARGO_BIN_EXE_tron-vanity` when cargo sets it, and otherwise `target/debug/tron-vanity` or `target/release/tron-vanity` under the manifest directory. The PTY test passes that path to Python as `TRON_VANITY_BIN`. A custom `CARGO_TARGET_DIR` breaks the fallback.

## License

Copyright (c) 2026 ZuZu Wallet.

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.

`publish = false` in `Cargo.toml`. This GitHub repository is the release. The crate is not published to crates.io.
