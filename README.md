# 🐙 Krakken-2048 / Krakken-Disk V5 — Test Harness

[![Tests](https://img.shields.io/badge/tests-18%2F18%20passing-brightgreen.svg)](#results)
[![Crypto Core](https://img.shields.io/badge/crypto--core-9%2F9-brightgreen.svg)](#1-crypto-core-suite)
[![Storage](https://img.shields.io/badge/storage--integrity-9%2F9-brightgreen.svg)](#2-storage-integrity-suite)
[![KAT](https://img.shields.io/badge/KAT-pinned-blue.svg)](#regression-pinning-kat)
[![Language: C11](https://img.shields.io/badge/C-C11-blue.svg)](#)
[![Deps: libsodium](https://img.shields.io/badge/deps-libsodium-orange.svg)](#requirements)
[![Platform: Linux x86--64](https://img.shields.io/badge/platform-Linux%20x86--64%20(AVX2)-lightgrey.svg)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)

A **standalone**, drop-anywhere test package for the Krakken-2048 permutation and
the Krakken-Disk **V5** on-disk sector format. It vendors only the crypto-core
and storage sources it needs — **no GTK, no FUSE, no Kyber tree** — so it can live
in a separate repository and run in CI with a single `make run`.

> **What this harness does and does not claim.** These tests verify the
> **implementation** is deterministic, invertible, tamper-evident, byte-for-byte
> stable (drift-locked via a pinned KAT), and that the V5 storage path round-trips
> and authenticates correctly. They **do not** constitute cryptanalysis or a
> security proof of the Krakken-2048 primitive — that lives in the design's
> academic write-ups. This is the *engineering-correctness* layer: the part that,
> if it regressed, would silently corrupt or expose user data.

---

## Quick start

```bash
make run        # build both suites and run them (non-zero exit on any failure)
```

Expected tail:

```
 9 checks run, 0 failed     # crypto-core
 9 checks run, 0 failed     # storage-integrity
```

### Requirements

| Dependency | Notes |
|---|---|
| **gcc** or **clang** | must support `-mavx2` (the permutation is AVX2-vectorized) |
| **libsodium** (dev) | `pkg-config --exists libsodium`; used by the storage suite (BLAKE2b MAC, RNG) |
| **pthreads** | sector-cache worker pools |
| **x86-64 with AVX2** | runtime requirement of the Krakken-2048 core |

Debian/Ubuntu:

```bash
sudo apt install build-essential pkg-config libsodium-dev
```

### Make targets

| Target | Action |
|---|---|
| `make` / `make all` | build `test_crypto_core` and `test_storage` |
| `make run` / `make check` | build + run the full suite (CI-friendly exit code) |
| `make clean` | remove built binaries |

---

## Layout

```
harness/
├── Makefile                 # standalone build (libsodium only)
├── README.md                # this file
└── src/
    ├── config.h             # trimmed standalone config (no Kyber include)
    ├── krakken_multi.c      # Krakken-2048 AVX2 permutation core
    ├── permut2048.{c,h}     # Permut-2048 sponge (absorb/squeeze/duplex)
    ├── sector_cache.{c,h}   # V5 sector encryptor + LRU cache (the storage path)
    ├── utils.{c,h}          # secure_zero / ct_memcmp / RNG helpers
    ├── test_crypto_core.c   # crypto-core suite (9 checks)
    └── test_storage.c       # storage-integrity suite (9 checks)
```

> `src/config.h` is a **trimmed copy** of the project's `config.h` carrying only
> the constants these tests need (sector sizes, nonce size, key size, sponge
> rate). If you bump those constants in the main project, mirror them here.

---

## What is tested

### 1. Crypto-core suite

Builds against `krakken_multi.c` + `permut2048.c` only.

| Check | Guards against |
|---|---|
| Permute determinism | non-reproducible permutation output |
| **Pinned KAT regression** | any silent change to keystream/tag bytes (would orphan existing volumes) |
| Hash determinism / single-bit sensitivity | broken sponge absorb/finalize |
| XOF prefix length-independence | inconsistent variable-length output |
| Duplex round-trip across the 160 B rate boundary | encrypt/decrypt desync at block edges |
| Ciphertext ≠ plaintext | accidental no-op encryption |
| Duplex tag detects a 1-bit flip | non-authenticating MAC |
| **Per-round avalanche measurement** | weak diffusion; quantifies round margin |

#### Regression pinning (KAT)

The permutation's output on a fixed seed is **pinned** in `test_crypto_core.c`
(`PIN[16]`). Any code change — a refactor, a compiler-flag change, an
"optimization" of the type-punned sponge load the source explicitly warns
against — that alters the output byte stream fails this check **before** it can
render existing on-disk volumes undecipherable.

#### Avalanche / diffusion

`test_crypto_core` flips a single input bit and measures how many of the 2048
output bits change after *N* rounds (ideal ≈ 1024 = 50%). This turns the
round-margin argument into a reproducible number anyone can regenerate.

### 2. Storage-integrity suite

Drives the **real V5 on-disk path** through the public sector-cache API
(`sector_encrypt_write` → `[ciphertext ‖ nonce ‖ tag]` record →
`cache_init`/`cache_get_sector`/`cache_flush_all`).

| Check | Guards against |
|---|---|
| All per-sector nonces distinct | nonce-reuse across sectors |
| Every sector decrypts to its plaintext | encrypt→disk→decrypt corruption |
| Out-of-range sector index rejected | OOB read/write |
| **Rewrite identical plaintext ⇒ fresh nonce** | regression to the v4 two-time-pad (the headline V5 fix) |
| Flip ciphertext byte ⇒ read fails | undetected data tampering |
| Flip nonce byte ⇒ read fails | nonce substitution (confirms nonce is MAC-authenticated) |
| Flip tag byte ⇒ read fails | forged/zeroed MAC |
| Modify → flush → reopen survives | unmount/remount data loss |

---

## Results

Reference run — **Linux x86-64 (AVX2), gcc -O3, libsodium**. Reproduce with `make run`.

<a name="1-crypto-core-suite"></a>
### crypto-core suite — 9 / 9 ✅

```
[permute] determinism + KAT regression
  [ ok ] permute is deterministic
    permute(seed) first16 = 9f23072dea73faa3408a7880ef66fd1c
  [ ok ] permute KAT matches pinned vector
[sponge] hash determinism + KAT
  [ ok ] hash is deterministic
  [ ok ] single-byte input change changes digest
  [ ok ] XOF prefix is length-independent
    hash(msg) = 7bec4711d9cbad09e050db4bf720bd3758543c8cc2da9c31c35afb94ad64b7f3
[duplex] encrypt/decrypt round-trip
  [ ok ] decrypt(encrypt(x)) == x across rate boundaries
  [ ok ] ciphertext differs from plaintext
[tag] duplex tag detects tampering
  [ ok ] 1-bit ciphertext flip changes tag
[avalanche] per-round bit diffusion (target ~1024/2048)
    round 1: avg=1023.4  min=964  max=1076 bits changed
    round 2: avg=1026.0  min=970  max=1076 bits changed
    round 3: avg=1025.2  min=981  max=1084 bits changed
    round 4: avg=1021.8  min=967  max=1069 bits changed
    round 5: avg=1022.3  min=976  max=1076 bits changed
    round 6: avg=1017.6  min=980  max=1072 bits changed
    round 7: avg=1021.0  min=955  max=1075 bits changed
    round 8: avg=1023.5  min=976  max=1070 bits changed
  [ ok ] full-round avalanche within +/-200 bits of ideal 1024/2048
 9 checks run, 0 failed
```

**Reading the avalanche table:** full statistical diffusion (~50% of all 2048
output bits flipping from a single input-bit change) is reached at **round 1**
and holds flat through **round 8** — the empirical complement to the design's
round-margin analysis.

<a name="2-storage-integrity-suite"></a>
### storage-integrity suite — 9 / 9 ✅

```
[storage] round-trip + per-sector nonce uniqueness
  [ ok ] all per-sector nonces are distinct
  [ ok ] cache_init succeeds
  [ ok ] every sector decrypts to its original plaintext
  [ ok ] out-of-range sector index rejected
  [ ok ] rewriting identical plaintext produces a fresh nonce (no 2-time pad)
[storage] tamper detection (cipher / nonce / tag)
  [ ok ] flipped ciphertext byte -> authenticated read fails
  [ ok ] flipped nonce byte -> authenticated read fails
  [ ok ] flipped tag byte -> authenticated read fails
[storage] modify -> flush -> reopen persistence (unmount/remount)
  [ ok ] modification survives flush + cache reopen
 9 checks run, 0 failed
```

**Total: 18 / 18 checks passing, 0 warnings.**

---

## Using this in CI

GitHub Actions example (`.github/workflows/harness.yml`):

```yaml
name: harness
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest   # GitHub's x86-64 runners support AVX2
    steps:
      - uses: actions/checkout@v4
      - name: Install deps
        run: sudo apt-get update && sudo apt-get install -y build-essential pkg-config libsodium-dev
      - name: Run harness
        run: make -C harness run
```

`make run` returns a non-zero exit code if any check fails, so a regression
fails the build.

---

## Scope / not covered

Out of scope for this package (documented so reviewers know the boundary):

- Full volume lifecycle (`volume_create` → Argon2id-1GB header derive → real FUSE
  mount → file I/O → unmount). Needs argon2/openssl/fuse3 and a mount point;
  belongs in a separate "slow" CI target.
- The `aead.c` >4 GB large-file streaming path.
- Thread-sanitizer runs over the parallel flush/prefetch worker pools.
- Cryptanalysis of Krakken-2048 (see the design's academic references).

---

## License

MIT — same as Krakken-Disk. See the parent project's `LICENSE`.
