# =============================================================================
#  Krakken-2048 / Krakken-Disk V5 — standalone test harness
#
#  Self-contained: vendors only the crypto-core and storage sources it needs.
#  No GTK, no FUSE, no Kyber tree required. Only dependency is libsodium.
#
#  Usage:
#     make            # build both test binaries
#     make run        # build + run the full suite
#     make check      # alias for run (CI-friendly, non-zero exit on failure)
#     make clean
#
#  Requirements:
#     - gcc/clang with AVX2 support (-mavx2)
#     - libsodium dev headers   (pkg-config --exists libsodium)
#     - pthreads
# =============================================================================

CC      ?= cc
CFLAGS  ?= -Wall -Wextra -O3 -mavx2 -march=native -Isrc
LDLIBS  ?= -lpthread

SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)

CORE_SRCS    = src/krakken_multi.c src/permut2048.c
STORAGE_SRCS = src/sector_cache.c src/utils.c $(CORE_SRCS)

BINS = test_crypto_core test_storage

.PHONY: all run check clean help
all: $(BINS)

test_crypto_core: src/test_crypto_core.c $(CORE_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

test_storage: src/test_storage.c $(STORAGE_SRCS)
	$(CC) $(CFLAGS) $(SODIUM_CFLAGS) $^ -o $@ $(LDLIBS) $(SODIUM_LIBS)

run check: all
	@echo "=== crypto-core suite ==="
	@./test_crypto_core
	@echo
	@echo "=== storage-integrity suite ==="
	@./test_storage

clean:
	rm -f $(BINS)

help:
	@echo "Targets: all (default), run/check, clean"
