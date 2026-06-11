/*
 * test_crypto_core.c — correctness + structural tests for the Krakken-2048
 * permutation and the Permut-2048 sponge.
 *
 * Two jobs:
 *   1. KAT / regression: pin the exact byte output of the primitive so any
 *      future change that silently alters the keystream or tag (the thing the
 *      source comments warn about) fails CI instead of corrupting volumes.
 *   2. Structural sanity: determinism, duplex round-trip, tag sensitivity, and
 *      a per-round avalanche measurement that makes the "full diffusion well
 *      before round 8" claim a checkable number rather than a slogan.
 *
 * These do NOT prove the cipher secure. They prove the implementation behaves
 * the way a sound construction must, and they lock its output against drift.
 *
 * Build: see tests/Makefile  (target: test_crypto_core)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "permut2048.h"

/* round-parameterized permute, exported by krakken_multi.c */
extern void krakken_permute_avx2(uint64_t state[32]);
extern void krakken_permute_avx2_rounds(uint64_t state[32], int rounds);
extern void init_rc_vectors_avx2(void);

/* ---- tiny test framework ------------------------------------------------ */
static int g_fail = 0, g_run = 0;
#define CHECK(cond, msg) do {                                   \
    g_run++;                                                    \
    if (!(cond)) { g_fail++; printf("  [FAIL] %s\n", msg); }    \
    else         {           printf("  [ ok ] %s\n", msg); }    \
} while (0)

static void hexdump(const char *label, const uint8_t *p, size_t n) {
    printf("    %s = ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static int popcount_buf(const uint8_t *a, const uint8_t *b, size_t n) {
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t x = a[i] ^ b[i];
        while (x) { c += x & 1; x >>= 1; }
    }
    return c;
}

/* ========================================================================= *
 * 1. Permutation determinism + KAT regression
 * ========================================================================= */
static void test_permute_kat(void) {
    printf("[permute] determinism + KAT regression\n");

    uint64_t a[32], b[32];
    for (int i = 0; i < 32; i++) a[i] = b[i] = 0;
    /* fixed non-trivial input */
    a[0] = b[0] = 0x0123456789abcdefULL;
    a[31] = b[31] = 0xfedcba9876543210ULL;

    krakken_permute_avx2(a);
    krakken_permute_avx2(b);
    CHECK(memcmp(a, b, sizeof(a)) == 0, "permute is deterministic");

    /* Regression pin: capture first 16 bytes of the permuted all-but-two-zero
     * state. The expected value is filled in on first run (see PIN below). A
     * change here means the on-disk keystream changed — exactly the silent
     * breakage the source comments warn about. */
    uint8_t out[16];
    memcpy(out, a, sizeof(out));
    hexdump("permute(seed) first16", out, sizeof(out));

    /* PIN: replace the all-zero array below with the printed value to lock it.
     * Left unset on purpose so the first committed run records the real vector. */
    static const uint8_t PIN[16] = {
        0x9f,0x23,0x07,0x2d,0xea,0x73,0xfa,0xa3,
        0x40,0x8a,0x78,0x80,0xef,0x66,0xfd,0x1c
    };
    int pin_set = 0;
    for (int i = 0; i < 16; i++) if (PIN[i]) pin_set = 1;
    if (pin_set)
        CHECK(memcmp(out, PIN, 16) == 0, "permute KAT matches pinned vector");
    else
        printf("  [note] KAT not yet pinned — copy printed vector into PIN[]\n");
}

/* ========================================================================= *
 * 2. Sponge hash: determinism + length independence + KAT
 * ========================================================================= */
static void test_hash(void) {
    printf("[sponge] hash determinism + KAT\n");

    const char *msg = "Krakken-Disk production readiness harness";
    uint8_t h1[32], h2[32];
    permut2048_hash((const uint8_t*)msg, strlen(msg), h1, sizeof(h1));
    permut2048_hash((const uint8_t*)msg, strlen(msg), h2, sizeof(h2));
    CHECK(memcmp(h1, h2, 32) == 0, "hash is deterministic");

    /* different message -> different digest */
    uint8_t h3[32];
    permut2048_hash((const uint8_t*)"krakken-disk production readiness harness",
                    strlen(msg), h3, sizeof(h3));
    CHECK(memcmp(h1, h3, 32) != 0, "single-byte input change changes digest");

    /* XOF length consistency: a longer squeeze must share its prefix with a
     * shorter one (same construction, arbitrary length). */
    uint8_t x64[64], x32[32];
    permut2048_xof((const uint8_t*)msg, strlen(msg), x64, sizeof(x64));
    permut2048_xof((const uint8_t*)msg, strlen(msg), x32, sizeof(x32));
    CHECK(memcmp(x64, x32, 32) == 0, "XOF prefix is length-independent");

    hexdump("hash(msg)", h1, 32);
}

/* ========================================================================= *
 * 3. Duplex encrypt/decrypt round-trip across rate boundaries
 * ========================================================================= */
static void test_duplex_roundtrip(void) {
    printf("[duplex] encrypt/decrypt round-trip\n");

    /* sizes chosen to straddle the 160-byte rate: under, exact, over, multi */
    size_t sizes[] = {1, 159, 160, 161, 320, 1000, 4096};
    int all_ok = 1, ct_differs = 1;

    for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        uint8_t *pt  = malloc(n), *ct = malloc(n), *rt = malloc(n);
        for (size_t i = 0; i < n; i++) pt[i] = (uint8_t)(i * 31 + 7);

        permut2048_ctx e; memset(&e, 0, sizeof(e)); e.rate = PERMUT2048_RATE;
        uint8_t key[32] = {0xA5};
        permut2048_absorb(&e, key, sizeof(key));
        permut2048_finalize(&e);
        permut2048_encrypt(&e, pt, ct, n);

        permut2048_ctx d; memset(&d, 0, sizeof(d)); d.rate = PERMUT2048_RATE;
        permut2048_absorb(&d, key, sizeof(key));
        permut2048_finalize(&d);
        permut2048_decrypt(&d, ct, rt, n);

        if (memcmp(pt, rt, n) != 0) all_ok = 0;
        if (n >= 16 && memcmp(pt, ct, n) == 0) ct_differs = 0;
        free(pt); free(ct); free(rt);
    }
    CHECK(all_ok, "decrypt(encrypt(x)) == x across rate boundaries");
    CHECK(ct_differs, "ciphertext differs from plaintext");
}

/* ========================================================================= *
 * 4. Tag sensitivity: a 1-bit ciphertext change must change the duplex tag
 * ========================================================================= */
static void test_tag_sensitivity(void) {
    printf("[tag] duplex tag detects tampering\n");

    uint8_t key[32] = {0x5C};
    uint8_t pt[200];
    for (int i = 0; i < 200; i++) pt[i] = (uint8_t)i;

    uint8_t ct[200], tag1[32], tag2[32];

    permut2048_ctx e; memset(&e, 0, sizeof(e)); e.rate = PERMUT2048_RATE;
    permut2048_absorb(&e, key, sizeof(key));
    permut2048_finalize(&e);
    permut2048_encrypt(&e, pt, ct, sizeof(pt));
    permut2048_squeeze_tag(&e, tag1, sizeof(tag1));

    /* flip one bit of ciphertext, recompute tag over the tampered stream by
     * decrypting then re-deriving — here we just re-run the tag path with a
     * flipped ct fed back through a fresh duplex to confirm tag changes. */
    uint8_t ct2[200]; memcpy(ct2, ct, sizeof(ct));
    ct2[100] ^= 0x01;

    permut2048_ctx d; memset(&d, 0, sizeof(d)); d.rate = PERMUT2048_RATE;
    uint8_t junk[200];
    permut2048_absorb(&d, key, sizeof(key));
    permut2048_finalize(&d);
    permut2048_decrypt(&d, ct2, junk, sizeof(ct2));
    permut2048_squeeze_tag(&d, tag2, sizeof(tag2));

    CHECK(memcmp(tag1, tag2, 32) != 0, "1-bit ciphertext flip changes tag");
}

/* ========================================================================= *
 * 5. Per-round avalanche — the round-margin claim, as a number
 *
 * Flip one input bit, run N rounds, measure how many of the 2048 output bits
 * change. A well-mixing permutation reaches ~1024 (50%) and stays there. This
 * lets you SEE at which round full diffusion sets in and how much margin the
 * 8-round count actually buys.
 * ========================================================================= */
static void test_avalanche_by_round(void) {
    printf("[avalanche] per-round bit diffusion (target ~1024/2048)\n");
    init_rc_vectors_avx2();

    const int TRIALS = 64;
    int worst_full = 0;          /* worst-case deviation from 1024 at 8 rounds */

    for (int r = 1; r <= 8; r++) {
        long sum = 0, mn = 2048, mx = 0;
        for (int t = 0; t < TRIALS; t++) {
            uint64_t base[32], flip[32];
            /* pseudo-random base from a simple LCG seeded by trial */
            uint64_t s = 0x9e3779b97f4a7c15ULL ^ ((uint64_t)t << 32);
            for (int i = 0; i < 32; i++) { s = s*6364136223846793005ULL+1; base[i]=s; }
            memcpy(flip, base, sizeof(base));
            int bit = (int)(s % 2048);
            flip[bit/64] ^= (1ULL << (bit % 64));

            krakken_permute_avx2_rounds(base, r);
            krakken_permute_avx2_rounds(flip, r);

            int d = popcount_buf((uint8_t*)base, (uint8_t*)flip, 256);
            sum += d; if (d < mn) mn = d; if (d > mx) mx = d;
        }
        double avg = (double)sum / TRIALS;
        printf("    round %d: avg=%.1f  min=%ld  max=%ld bits changed\n",
               r, avg, mn, mx);
        if (r == 8) {
            int dev_lo = 1024 - (int)mn, dev_hi = (int)mx - 1024;
            worst_full = dev_lo > dev_hi ? dev_lo : dev_hi;
        }
    }
    /* At full rounds, every trial should sit near 50%. Allow generous slack
     * (statistical, 64 trials): within +/-200 of 1024 across all trials. */
    CHECK(worst_full <= 200,
          "full-round avalanche within +/-200 bits of ideal 1024/2048");
}

int main(void) {
    printf("=================================================================\n");
    printf(" Krakken-2048 crypto-core test harness\n");
    printf("=================================================================\n");
    init_rc_vectors_avx2();

    test_permute_kat();
    test_hash();
    test_duplex_roundtrip();
    test_tag_sensitivity();
    test_avalanche_by_round();

    printf("-----------------------------------------------------------------\n");
    printf(" %d checks run, %d failed\n", g_run, g_fail);
    printf("=================================================================\n");
    return g_fail ? 1 : 0;
}
