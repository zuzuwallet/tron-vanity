# tron-vanity

An offline, security-focused vanity address generator for **TRON mainnet accounts**.

`tron-vanity` searches for a TRON address beginning with a prefix you choose, for example:

```text
THZZZ...
```

Each candidate uses a fresh 32-byte secp256k1 private-key candidate from the operating-system CSPRNG. A winning key is independently verified before it is encrypted and saved.

The private key is **not printed during generation**.

---

## One important TRON prefix rule

Not every Base58 string beginning with `T` is a possible TRON account address.

For example:

```text
TZuZu
```

is impossible and is rejected before a search begins.

A TRON mainnet account address is the Base58Check encoding of a 25-byte payload whose first byte is:

```text
0x41
```

That fixes the address to a specific numeric range.

The complete range encodes between:

```text
T9yD14Nj9j7xAB4dbGeiX9h8unkKDDv9ZR
```

and:

```text
TZJozAg1ruapycCicgz31GxvYJ1FvTVysk
```

So prefixes such as:

```text
TZZ
TZK
TZuZu
```

cannot occur.

A reachable example with four vanity characters is:

```text
THZZZ
```

where the vanity-controlled portion is:

```text
HZZZ
```

---

# Highlights

- Offline TRON mainnet vanity address generation
- Fresh 32-byte OS CSPRNG draw for every candidate
- Invalid secp256k1 scalars rejected rather than reduced modulo the curve order
- libsecp256k1 public-key derivation
- Correct TRON Keccak-256 address derivation
- Negative tests against NIST SHA3-256
- Multi-threaded search
- Prefix feasibility and difficulty estimation
- Built-in published TRON and cryptographic test vectors
- Independent verification using `k256`, `sha3`, `bitcoin_hashes`, and `bs58`
- Argon2id + ChaCha20-Poly1305 encrypted wallet files
- Best-effort secret-memory cleanup
- Atomic, no-overwrite wallet publication
- Wallet files created with mode `0600`
- Terminal-only private-key export
- No runtime RPC, block explorer, telemetry, HTTP client, or update checker
- `#![forbid(unsafe_code)]` in this crate

The compiled generator is designed to work with networking disabled.

---

# What it does

For each candidate, the program:

1. Reads exactly **32 bytes** from the operating-system CSPRNG using `getrandom`.
2. Accepts them only when they represent a valid secp256k1 scalar in `1..=n-1`.
3. Derives the **uncompressed** SEC1 public key with libsecp256k1.
4. Removes the leading `0x04` byte.
5. Computes Keccak-256 over the remaining 64-byte `X || Y` public key.
6. Takes the final 20 bytes of that digest.
7. Prepends the TRON address byte:

```text
41
```

8. Adds the four-byte Base58Check checksum.
9. Checks the resulting 25-byte payload against the requested prefix range.
10. Builds the Base58 text only when the numeric candidate falls inside that range.
11. Performs a final textual prefix check.

A winning candidate is then checked again through a separate implementation stack before any wallet file is created.

The private scalar is encrypted and stored locally.

It is **not displayed during generation**.

---

# Scope

This project intentionally has a narrow scope.

It supports:

- TRON mainnet account addresses
- secp256k1 private keys
- vanity prefix searching
- encrypted standalone key storage
- wallet verification
- offline private-key export as lowercase hexadecimal

It does **not** provide:

- HD derivation
- mnemonics
- BIP-39
- BIP-44 wallet management
- transaction signing
- transaction construction
- contract addresses
- SM2 keys
- node RPC
- block explorer access

A normal TRON HD wallet commonly uses:

```text
m/44'/195'/0'/0/index
```

This project does not.

It generates one standalone random key.

---

# Important: do not reuse the private key on EVM chains

TRON derives the same 20-byte account identifier that Ethereum derives from the same secp256k1 public key.

That means the same private scalar corresponds to:

```text
TRON:
41 || 20-byte account id
→ Base58Check T... address
```

and:

```text
Ethereum / EVM:
0x || same 20-byte account id
```

Do **not** import an exported TRON vanity private key into Ethereum or another EVM wallet.

Doing so couples the security of assets on both chains to the same private key.

---

# Building on Fedora

The recommended workflow is:

> **Build and inspect the project while online, then disconnect before generating a real wallet.**

The recorded development environment used:

```text
rustc 1.99.0
cargo 1.99.0
```

Install the required tools:

```bash
sudo dnf install gcc python3

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

rustup component add rustfmt clippy

cargo install cargo-audit cargo-deny
```

`python3` is required for the PTY integration test.

`secp256k1-sys` compiles native C code, so a working C compiler is required.

Before building, a restrictive umask is recommended:

```bash
umask 077
```

Run the normal checks:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release
```

Read:

```text
Cargo.toml
Cargo.lock
```

and the source before trusting the resulting binary.

`cargo audit` and `cargo deny` require network access to obtain advisory information.

The `tron-vanity` binary itself does not.

---

# Recommended offline workflow

After building and reviewing the project, disconnect networking.

For example:

```bash
nmcli networking off
```

or physically disconnect the machine.

Then run:

```bash
./target/release/tron-vanity self-test
```

Generate an address:

```bash
./target/release/tron-vanity generate THZZZ
```

Verify the encrypted wallet:

```bash
./target/release/tron-vanity verify THZZZ-wallet.json
```

For wallet storage, create a private directory:

```bash
mkdir -m 700 ~/wallet-output
```

and use:

```bash
umask 077
```

in the shell that runs generation.

Back up the encrypted wallet before funding the address.

For an offline key-generation environment, also consider disabling or avoiding:

- shared clipboard
- shared folders
- VM snapshots containing memory
- unencrypted swap
- hibernation
- crash dumps

The host operating system and hypervisor remain part of your trust boundary.

---

# Commands

### Self-test

```bash
tron-vanity self-test
```

Runs the built-in cryptographic known-answer checks.

### Generate

```bash
tron-vanity generate THZZZ
```

Choose the number of worker threads:

```bash
tron-vanity generate THZZZ --threads 16
```

Choose the output file:

```bash
tron-vanity generate THZZZ \
  --threads 16 \
  --output THZZZ-wallet.json
```

### Verify

```bash
tron-vanity verify THZZZ-wallet.json
```

Decrypts the wallet, derives the address again, and verifies it independently.

### Export

```bash
tron-vanity export THZZZ-wallet.json
```

Displays the private key after explicit confirmation.

---

# Generation behavior

`generate` defaults to:

```text
std::thread::available_parallelism()
```

clamped to:

```text
1..=256
```

Values of `0` or greater than `256` are rejected.

The default wallet filename is:

```text
{prefix}-wallet.json
```

For example:

```text
THZZZ-wallet.json
```

Existing destination files are never overwritten.

There is no overwrite flag.

The parent directory must already exist.

If it is writable by group or others, the program prints a warning and continues.

For normal offline use:

```bash
mkdir -m 700 ~/wallet-output
```

is recommended.

---

# Search difficulty

Before searching, the program displays:

- target prefix
- vanity-controlled portion
- approximate expected attempts
- approximate 50% probability point
- a simple `58^N` comparison

For:

```text
THZZZ
```

the current model gives:

```text
Target: THZZZ
Vanity portion: HZZZ
Difficulty: approximately 4,553,521
50% probability after approximately 3,156,260
Per-character approximation: 58^4 = 11,316,496
There is no guaranteed completion time.
```

The `58^4` number is shown only as a familiar comparison.

It is **not** the actual estimate for this prefix.

---

# Why `58^4` is not the right difficulty for `THZZZ`

Four fully unconstrained Base58 characters would give:

```text
58^4 = 11,316,496
```

But characters after the leading `T` are not uniformly distributed across the full Base58 alphabet.

For example, the second character can only be one of:

```text
9ABCDEFGHJKLMNPQRSTUVWXYZ
```

and the edge values represent only partial numeric buckets.

Under the model used by this generator:

```text
THZZZ
```

covers a fraction of the valid `0x41` address range corresponding to an expected search cost of approximately:

```text
4,553,521
```

The approximate 50% point is:

```text
3,156,260
```

This remains a statistical model, not a wall-clock guarantee.

---

# Prefix rules

A requested prefix must be a possible TRON account address.

Examples:

| Prefix | Result |
|---|---|
| `THZZZ` | accepted |
| `TZJ` | accepted |
| `TZuZu` | rejected — outside the valid `0x41` range |
| `TZZ` | rejected |
| `TZK` | rejected |
| `Tz` | rejected — impossible second character |
| `ZuZu` | rejected — account addresses begin with `T` |
| `tZuZu` | rejected — account addresses begin with uppercase `T` |
| `T0` | rejected — `0` is not Base58 |
| prefix longer than 34 characters | rejected |

The Base58 alphabet is:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

and excludes:

```text
0 O I l
```

Extremely rare prefixes whose expected attempt count does not fit within the implementation's counter are rejected before searching.

---

# Passphrases

There is no:

```text
--password
```

flag.

Passphrases are read directly from the terminal with echo disabled.

When creating a new wallet, the passphrase must contain:

- at least **12 Unicode scalar values**
- no more than **1024 bytes**

The value is not trimmed.

The 12-character minimum is only intended to prevent obvious mistakes.

It is **not** a password-strength guarantee.

Use a long, unique, randomly generated passphrase for anything you intend to fund.

`verify` and `export` can still open older wallets using a shorter non-empty passphrase so existing wallet files are not stranded.

---

# Ctrl-C and cancellation

Cancellation is designed to fail safely.

Ctrl-C sets an atomic flag rather than calling:

```text
process::exit()
```

During a search:

- worker threads observe the flag and stop;
- a candidate racing with cancellation is discarded;
- no wallet is written.

At a passphrase prompt:

- terminal echo is restored;
- the command cancels normally;
- no public address or private key is printed.

During Argon2:

- the current operation is allowed to finish internally;
- the cancellation flag is checked before success information is printed.

`export` checks the flag again after hexadecimal encoding and immediately before displaying the private key.

Once terminal output itself begins, it cannot be taken back.

---

# When the public address is shown

The public `T...` address is deliberately withheld until the encrypted wallet has been successfully published.

The sequence is:

```text
match found
      ↓
passphrase entered
      ↓
wallet encrypted
      ↓
temporary file written
      ↓
file fsynced
      ↓
final destination published
      ↓
parent directory fsynced
      ↓
raw key and passphrase dropped
      ↓
FOUND
Address: T...
```

If wallet persistence fails, the address is not shown.

If another file appears at the destination while generation is running, publication is refused.

---

# Verifying a wallet

Run:

```bash
tron-vanity verify THZZZ-wallet.json
```

The program:

1. validates the wallet format;
2. derives the Argon2id encryption key;
3. authenticates and decrypts the private scalar;
4. validates the secp256k1 private key;
5. derives the TRON address;
6. runs the independent verification path;
7. compares the derived address with the stored address.

A successful result looks like:

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

The private key and passphrase are dropped before this public output is printed.

---

# Exporting the private key

Run:

```bash
tron-vanity export THZZZ-wallet.json
```

`export` is the only command that deliberately prints the private key.

Both stdin and stdout must be terminals.

The command prints a warning and requires:

```text
EXPORT
```

before asking for the wallet passphrase.

The private key is displayed as:

```text
64 lowercase hexadecimal characters
```

with **no** `0x` prefix.

For example, the format is:

```text
Private key:
0123abcd...
```

It is **not** Bitcoin WIF.

> [!CAUTION]
> Anyone with this 32-byte private key can control the corresponding TRON account.

Never paste it into:

- a website
- an AI/chat service
- an issue report
- email
- a shell command
- an online wallet checker

After recording it securely, clear the terminal scrollback or close the terminal session.

---

# TRON address derivation

Each candidate starts as:

```text
32 random bytes
```

The derivation is:

```text
32-byte candidate
       ↓
valid secp256k1 scalar?
       ↓ yes
uncompressed public key
       ↓
remove 0x04
       ↓
Keccak-256(X || Y)
       ↓
last 20 bytes
       ↓
prepend 0x41
       ↓
double-SHA-256 checksum
       ↓
Base58
       ↓
T... address
```

## 1. Private scalar

The secp256k1 curve order is:

```text
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

A random candidate is accepted only when:

```text
1 <= key < n
```

Zero and values greater than or equal to the curve order are discarded.

They are not reduced modulo `n`.

## 2. Public key

The primary path derives an uncompressed SEC1 public key:

```text
04 || X || Y
```

The leading:

```text
04
```

is removed before hashing.

## 3. Keccak-256

TRON uses **Keccak-256**.

It does **not** use NIST SHA3-256.

These are different functions.

The project contains explicit negative tests so a future change from:

```text
Keccak-256
```

to:

```text
SHA3-256
```

fails the test suite.

## 4. Account ID

The account ID is:

```text
last 20 bytes of Keccak-256(X || Y)
```

or equivalently:

```text
hash[12..32]
```

for a 32-byte digest.

## 5. Address prefix

TRON prepends:

```text
41
```

to the 20-byte account identifier.

## 6. Base58Check

The checksum is the first four bytes of:

```text
SHA256(
    SHA256(
        0x41 || account_id
    )
)
```

The resulting 25 bytes are Base58 encoded into the familiar:

```text
T...
```

address.

---

# Keccak-256 vs SHA3-256

This difference is important.

For the empty string:

| Function | Digest |
|---|---|
| Keccak-256 | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| SHA3-256 | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` |

For:

```text
abc
```

Keccak-256 is:

```text
4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
```

The project locks these values in its self-tests.

---

# Independent verification

A winning candidate is not trusted merely because the primary implementation produced the desired prefix.

The primary path uses:

- libsecp256k1
- `tiny-keccak`
- `sha2`
- this crate's Base58Check implementation

The independent verification path uses:

- `k256 0.13.4` for the secp256k1 public key
- `sha3::Keccak256` for Keccak
- `bitcoin_hashes 0.16` for the double-SHA-256 checksum
- `bs58 0.5.1` for Base58 text

The `bs58` checksum feature is deliberately disabled, so the independent checksum does not fall back to the primary `sha2` implementation.

The two paths compare:

- the full 65-byte public key;
- the 20-byte account ID;
- the final Base58 address.

A mismatch is treated as fatal.

No wallet is written.

---

# Known-answer tests

Self-tests run before vanity generation.

A failure aborts before any wallet is written.

Examples include:

| Check | Expected value |
|---|---|
| SHA-256 of empty input | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Keccak-256 of empty input | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| SHA3-256 of empty input | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` |
| Keccak-256 of `abc` | `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45` |
| private key `1` address | `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC` |
| documented hex/address pair | `418840E6...ED808` → `TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL` |
| TronWeb published address | `TXeSp72o5r185cmeGxFDkdCZFdJS1TAyHw` |

The repository also contains negative checks for:

- hashing the `0x04` prefix;
- using SHA3-256 instead of Keccak-256;
- taking the wrong 20-byte portion of the digest.

Published keys or public vectors used by the tests are test data only.

---

# Private-key format

The exported private key is the raw secp256k1 scalar encoded as:

```text
64 lowercase hexadecimal characters
```

There is no:

```text
0x
```

prefix.

Uppercase hexadecimal and prefixed forms are rejected by the import/parser path.

The encrypted wallet stores the raw 32-byte scalar rather than the text representation.

---

# Encrypted wallet format

The wallet contains the encrypted **32-byte private scalar**.

It does not store plaintext hexadecimal text.

Version 1 uses:

| Property | Value |
|---|---|
| KDF | Argon2id |
| Argon2 version | 19 / `0x13` |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 random bytes |
| Output key | 32 bytes |
| AEAD | ChaCha20-Poly1305 |
| Nonce | 12 random bytes |
| Plaintext | 32-byte private key |
| Ciphertext | 48 bytes |
| Wallet mode | `0600` |

Authenticated metadata includes:

```text
tron-vanity-wallet-v1
public address
account
uncompressed
mainnet
```

Changing the stored address, address type, public-key encoding, or network label causes authentication to fail.

Production wallet files must use the expected production Argon2 settings.

Unexpected KDF settings are rejected before Argon2 is run.

---

# Wallet filesystem safety

Wallet creation uses a temporary file in the destination directory.

The process is:

```text
create temp file with O_CREAT | O_EXCL
        ↓
verify mode 0600
        ↓
write encrypted wallet
        ↓
fsync file
        ↓
hard-link to final destination
        ↓
refuse existing destination
        ↓
remove temporary name
        ↓
fsync parent directory
```

There is no overwrite mode.

If directory synchronization fails after publication, the command returns an error and does not display the address.

The file may still exist and can be checked later with:

```bash
tron-vanity verify <wallet>
```

Wallet reads:

- open the path once;
- use Linux `O_NOFOLLOW`;
- reject symbolic links;
- read metadata and contents from the same descriptor;
- reject files larger than 1 MiB.

These filesystem protections currently target Fedora/Linux.

---

# Zeroization

Secret data uses the `zeroize` crate where practical.

This includes:

- candidate private-key buffers
- Argon2 output
- Argon2 working memory
- AEAD key material
- decrypted wallet plaintext
- exported hexadecimal private-key strings
- secret Base58 working buffers where used

libsecp256k1's temporary `SecretKey` object is protected by a borrowed guard that calls:

```text
non_secure_erase
```

when it goes out of scope.

The libsecp256k1 context is also randomized with fresh OS randomness before secret-key operations.

This remains **best-effort memory hygiene**.

It cannot guarantee removal of:

- compiler-generated copies
- CPU register copies
- allocator copies
- dependency-internal temporaries
- swap
- hibernation
- crash dumps
- VM snapshots
- terminal scrollback after export

A process terminated with `SIGKILL` also does not run normal destructors.

---

# Threat model

The project assumes:

- the operating-system CSPRNG is trustworthy;
- the CPU is trustworthy;
- the OS is not already compromised;
- the Rust toolchain is trustworthy;
- dependencies have not been maliciously substituted.

The project tries to defend against mistakes such as:

- hashing the SEC1 `0x04` prefix;
- using SHA3-256 instead of Keccak-256;
- selecting the wrong 20 digest bytes;
- using the wrong TRON address prefix;
- incorrect Base58Check;
- saving a key in a world-readable file;
- passing a password on the command line;
- silently overwriting an existing wallet;
- displaying an address before its encrypted wallet exists;
- accepting damaged or substituted ciphertext;
- continuing a search after a winning candidate is found.

It does **not** solve:

- malware
- keyloggers
- root access
- physical memory attacks
- side-channel attacks
- weak but sufficiently long passphrases
- compromised dependencies
- fake wallet software
- bugs inside libsecp256k1, `k256`, `sha3`, `argon2`, or `chacha20poly1305`

---

# Limitations

A few important limitations are intentional:

- The program does not ask the TRON network whether an address is already active or used.
- It does not activate an account.
- It does not sign transactions.
- It does not build transactions.
- It does not create an HD wallet.
- Search estimates are probabilistic.
- Workers draw fresh random keys rather than splitting the keyspace deterministically.
- A process killed abruptly may not run secret-zeroization destructors.
- Extremely difficult searches may hit the attempt-counter limit without finding a match.
- Side-channel attacks remain out of scope.
- The same private key maps to an Ethereum/EVM address and should not be reused there.

---

# Benchmarks

The normal miss path performs approximately:

```text
getrandom(32 bytes)
+
secp256k1 uncompressed public-key derivation
+
Keccak-256
+
double-SHA-256 checksum
+
25-byte prefix-range comparison
```

Base58 text is built only when the numeric payload falls inside the requested prefix range.

Run Criterion benchmarks with:

```bash
cargo bench --bench derive
```

Benchmark results vary with:

- CPU model
- system load
- VM configuration
- power-management settings
- thermal throttling
- thread count
- `getrandom` contention

Do not treat one benchmark run as a guaranteed search rate.

---

# Dependency and security review

Notable direct dependencies include:

| Crate | Role |
|---|---|
| `argon2` | wallet KDF |
| `bitcoin_hashes` | independent double SHA-256 |
| `bs58` | independent Base58 text |
| `chacha20poly1305` | authenticated wallet encryption |
| `getrandom` | operating-system CSPRNG |
| `k256` | independent secp256k1 implementation |
| `secp256k1` | primary libsecp256k1 implementation |
| `sha2` | primary Base58Check checksum |
| `sha3` | independent Keccak and SHA3 negative tests |
| `tiny-keccak` | primary Keccak-256 |
| `zeroize` | secret-memory cleanup |
| `rpassword` | terminal passphrase input |
| `clap` | command-line interface |

Security/dependency checks used during development include:

```bash
cargo audit

cargo deny check advisories bans licenses sources
```

The compiled generator does not contain a normal RPC/HTTP networking stack.

Generation and verification are designed to work offline.

---

# Development checks

Before creating a release:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release

./target/release/tron-vanity self-test
```

The integration suite includes PTY tests covering:

- Ctrl-C at passphrase prompts
- terminal-echo restoration
- cancellation during generation
- suppression of public/private output after cancellation
- output-file collisions during generation

Those tests require `python3`.

---

# Repository layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore
LICENSE-APACHE
LICENSE-MIT
NOTICE
README.md

src/
├── lib.rs
├── main.rs
├── error.rs
├── secret.rs
├── hexutil.rs
├── self_test.rs
├── independent.rs
├── verify.rs
├── search.rs
├── wallet.rs
└── tron/
    ├── base58.rs
    ├── hash.rs
    ├── hexkey.rs
    ├── keys.rs
    ├── prefix.rs
    └── uint.rs

tests/
├── vectors.rs
├── prefix.rs
├── search.rs
├── cli.rs
├── pty_ctrlc.rs
└── pty_ctrlc.py

benches/
└── derive.rs
```

---

# References

The implementation was developed against:

- TRON Developer Hub — Account
- TRON Developer Hub — Encoding
- TronWeb `createAccount` documentation
- SEC 1 secp256k1 public-key conventions
- Keccak-256 published test vectors
- FIPS 180-4 SHA-256 vectors
- RFC 9106 — Argon2
- RFC 8439 — ChaCha20-Poly1305

---

# License

Copyright © 2026 ZuZu Wallet

https://ZuZuWallet.com

Support@ZuZuWallet.com

Licensed under either:

- Apache License, Version 2.0 — `LICENSE-APACHE`
- MIT License — `LICENSE-MIT`

at your option.

`publish = false` is set in `Cargo.toml`.

The GitHub repository is the distribution source; this crate is not published to crates.io.
