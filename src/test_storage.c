/*
 * test_storage.c — on-disk sector integrity tests for Krakken-Disk V5.
 *
 * Exercises the REAL storage path through the public sector-cache API:
 *   sector_encrypt_write()  -> on-disk [cipher][nonce][tag] record
 *   cache_init / cache_get_sector / cache_mark_dirty / cache_flush_all
 *
 * What it guards (the failures most likely to actually eat a user's data):
 *   1. Encrypt-then-decrypt round-trip through the on-disk format.
 *   2. Per-sector random-nonce uniqueness — across sectors AND across
 *      rewrites of the same sector (the v5 two-time-pad fix; if this ever
 *      regresses to a deterministic nonce the keystream repeats).
 *   3. Tamper detection — flipping any byte of cipher/nonce/tag must make the
 *      authenticated read fail (no silent plaintext corruption).
 *   4. Persistence round-trip — write via cache, flush, re-open cache, read
 *      back: simulates unmount -> remount.
 *   5. Bounds — out-of-range sector index is rejected.
 *
 * Build: see tests/Makefile (target: test_storage). Needs libsodium.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sodium.h>

#include "config.h"
#include "sector_cache.h"

/* Must mirror sector_cache.c's private record layout. */
#define PER_SECTOR_MAC_SIZE 32
#define SECTOR_RECORD_SIZE  (VFS_SECTOR_SIZE + SECTOR_NONCE_SIZE + PER_SECTOR_MAC_SIZE)

extern void init_rc_vectors_avx2(void);

static int g_fail = 0, g_run = 0;
#define CHECK(cond, msg) do {                                   \
    g_run++;                                                    \
    if (!(cond)) { g_fail++; printf("  [FAIL] %s\n", msg); }    \
    else         {           printf("  [ ok ] %s\n", msg); }    \
} while (0)

#define NSECT 16
#define DATA_OFFSET 4096   /* pretend the crypto header occupies one block */

/* Fill a temp file with NSECT freshly-encrypted sectors. Returns FILE* (rw). */
static FILE *make_volume(const char *path, const uint8_t *file_key,
                         uint8_t plain[NSECT][VFS_SECTOR_SIZE]) {
    FILE *f = fopen(path, "wb+");
    if (!f) { perror("fopen"); exit(2); }

    /* header placeholder */
    uint8_t hdr[DATA_OFFSET];
    memset(hdr, 0, sizeof(hdr));
    fwrite(hdr, 1, sizeof(hdr), f);

    for (int i = 0; i < NSECT; i++) {
        for (int j = 0; j < VFS_SECTOR_SIZE; j++)
            plain[i][j] = (uint8_t)((i * 131 + j * 7 + 17) & 0xff);
        if (fseeko(f, (off_t)DATA_OFFSET + (off_t)i * SECTOR_RECORD_SIZE, SEEK_SET) != 0)
            { perror("fseeko"); exit(2); }
        if (sector_encrypt_write(f, (uint64_t)i, file_key, plain[i]) != 0)
            { fprintf(stderr, "sector_encrypt_write failed\n"); exit(2); }
    }
    fflush(f);
    return f;
}

/* Read a stored record's nonce field straight from disk. */
static void read_nonce(FILE *f, int idx, uint8_t out[SECTOR_NONCE_SIZE]) {
    off_t off = (off_t)DATA_OFFSET + (off_t)idx * SECTOR_RECORD_SIZE + VFS_SECTOR_SIZE;
    fseeko(f, off, SEEK_SET);
    if (fread(out, 1, SECTOR_NONCE_SIZE, f) != SECTOR_NONCE_SIZE)
        { fprintf(stderr, "read_nonce short read\n"); exit(2); }
}

/* ========================================================================= */
static void test_roundtrip_and_nonces(const char *path) {
    printf("[storage] round-trip + per-sector nonce uniqueness\n");

    uint8_t file_key[KEY_SIZE], master_key[KEY_SIZE];
    randombytes_buf(file_key, sizeof(file_key));
    randombytes_buf(master_key, sizeof(master_key));

    uint8_t plain[NSECT][VFS_SECTOR_SIZE];
    FILE *f = make_volume(path, file_key, plain);

    /* nonce uniqueness across all sectors */
    uint8_t nonces[NSECT][SECTOR_NONCE_SIZE];
    for (int i = 0; i < NSECT; i++) read_nonce(f, i, nonces[i]);
    int unique = 1;
    for (int i = 0; i < NSECT; i++)
        for (int j = i + 1; j < NSECT; j++)
            if (memcmp(nonces[i], nonces[j], SECTOR_NONCE_SIZE) == 0) unique = 0;
    CHECK(unique, "all per-sector nonces are distinct");

    /* decrypt round-trip through the cache */
    sector_cache_t *c = cache_init(f, master_key, file_key, 64,
                                   DATA_OFFSET, NSECT);
    CHECK(c != NULL, "cache_init succeeds");

    int rt_ok = 1;
    for (int i = 0; i < NSECT; i++) {
        uint8_t *data = NULL;
        if (cache_get_sector(c, (uint64_t)i, &data) != 0 || !data) { rt_ok = 0; break; }
        if (memcmp(data, plain[i], VFS_SECTOR_SIZE) != 0) { rt_ok = 0; break; }
    }
    CHECK(rt_ok, "every sector decrypts to its original plaintext");

    /* out-of-range index rejected */
    uint8_t *d = NULL;
    CHECK(cache_get_sector(c, NSECT, &d) != 0, "out-of-range sector index rejected");

    /* rewrite the same sector twice -> nonce must change each time */
    uint8_t n_before[SECTOR_NONCE_SIZE], n_after[SECTOR_NONCE_SIZE];
    read_nonce(f, 3, n_before);
    fseeko(f, (off_t)DATA_OFFSET + (off_t)3 * SECTOR_RECORD_SIZE, SEEK_SET);
    sector_encrypt_write(f, 3, file_key, plain[3]);   /* same plaintext! */
    fflush(f);
    read_nonce(f, 3, n_after);
    CHECK(memcmp(n_before, n_after, SECTOR_NONCE_SIZE) != 0,
          "rewriting identical plaintext produces a fresh nonce (no 2-time pad)");

    cache_destroy(c);   /* flushes; closes nothing — we still own f? */
    /* cache_destroy does not fclose; close ourselves */
    fclose(f);
}

/* ========================================================================= */
static void test_tamper_detection(const char *path) {
    printf("[storage] tamper detection (cipher / nonce / tag)\n");

    uint8_t file_key[KEY_SIZE], master_key[KEY_SIZE];
    randombytes_buf(file_key, sizeof(file_key));
    randombytes_buf(master_key, sizeof(master_key));
    uint8_t plain[NSECT][VFS_SECTOR_SIZE];
    FILE *f = make_volume(path, file_key, plain);

    /* offsets within record 5 for the three fields */
    off_t base = (off_t)DATA_OFFSET + (off_t)5 * SECTOR_RECORD_SIZE;
    struct { const char *name; off_t off; } spots[] = {
        { "ciphertext byte", base + 10 },
        { "nonce byte",      base + VFS_SECTOR_SIZE + 2 },
        { "tag byte",        base + VFS_SECTOR_SIZE + SECTOR_NONCE_SIZE + 1 },
    };

    for (size_t s = 0; s < sizeof(spots)/sizeof(spots[0]); s++) {
        /* read original byte, flip it on disk */
        uint8_t orig;
        fseeko(f, spots[s].off, SEEK_SET);
        if (fread(&orig, 1, 1, f) != 1) { fprintf(stderr, "read fail\n"); exit(2); }
        uint8_t bad = orig ^ 0x01;
        fseeko(f, spots[s].off, SEEK_SET); fwrite(&bad, 1, 1, f); fflush(f);

        sector_cache_t *c = cache_init(f, master_key, file_key, 64,
                                       DATA_OFFSET, NSECT);
        uint8_t *data = NULL;
        int rc = cache_get_sector(c, 5, &data);
        char msg[64]; snprintf(msg, sizeof(msg),
                               "flipped %s -> authenticated read fails", spots[s].name);
        CHECK(rc != 0, msg);
        cache_destroy(c);

        /* restore for next iteration */
        fseeko(f, spots[s].off, SEEK_SET); fwrite(&orig, 1, 1, f); fflush(f);
    }
    fclose(f);
}

/* ========================================================================= */
static void test_persistence(const char *path) {
    printf("[storage] modify -> flush -> reopen persistence (unmount/remount)\n");

    uint8_t file_key[KEY_SIZE], master_key[KEY_SIZE];
    randombytes_buf(file_key, sizeof(file_key));
    randombytes_buf(master_key, sizeof(master_key));
    uint8_t plain[NSECT][VFS_SECTOR_SIZE];
    FILE *f = make_volume(path, file_key, plain);

    /* modify sector 7 through the cache, flush, destroy */
    sector_cache_t *c = cache_init(f, master_key, file_key, 64, DATA_OFFSET, NSECT);
    uint8_t *data = NULL;
    cache_get_sector(c, 7, &data);
    for (int j = 0; j < VFS_SECTOR_SIZE; j++) data[j] = (uint8_t)(0xC0 ^ j);
    cache_mark_dirty(c, 7);
    cache_flush_all(c);
    cache_destroy(c);
    fclose(f);

    /* reopen file fresh, read sector 7 back */
    FILE *f2 = fopen(path, "rb+");
    sector_cache_t *c2 = cache_init(f2, master_key, file_key, 64, DATA_OFFSET, NSECT);
    uint8_t *d2 = NULL;
    int rc = cache_get_sector(c2, 7, &d2);
    int match = 1;
    if (rc != 0 || !d2) match = 0;
    else for (int j = 0; j < VFS_SECTOR_SIZE; j++)
        if (d2[j] != (uint8_t)(0xC0 ^ j)) { match = 0; break; }
    CHECK(match, "modification survives flush + cache reopen");
    cache_destroy(c2);
    fclose(f2);
}

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 2; }
    init_rc_vectors_avx2();

    printf("=================================================================\n");
    printf(" Krakken-Disk V5 storage-integrity test harness\n");
    printf("=================================================================\n");

    char tmpl[] = "/tmp/krakken_test_XXXXXX";
    int fd = mkstemp(tmpl); if (fd >= 0) close(fd);

    test_roundtrip_and_nonces(tmpl);
    test_tamper_detection(tmpl);
    test_persistence(tmpl);

    unlink(tmpl);

    printf("-----------------------------------------------------------------\n");
    printf(" %d checks run, %d failed\n", g_run, g_fail);
    printf("=================================================================\n");
    return g_fail ? 1 : 0;
}
