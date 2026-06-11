#ifndef CONFIG_H
#define CONFIG_H

/*
 * config.h — STANDALONE HARNESS COPY.
 *
 * This is a trimmed version of the Krakken-Disk project config.h containing
 * only the constants the crypto-core and storage test harness needs. The KEM /
 * Kyber / X448 header constants and the "kyber/params.h" include are removed so
 * the harness builds without the full project tree. The values below MUST match
 * the project's config.h or the on-disk record layout assumptions diverge.
 */

/* Application identity (informational) */
#define APP_NAME "Krakken-Disk"
#define APP_VERSION "5.0.0"

/* Cryptography constants */
#define KEY_SIZE       64
#define NONCE_SIZE     12
#define TAG_SIZE       32
#define SALT_SIZE      16
#define STREAM_BUFFER_SIZE (1024*1024)

/* Permut-2048 constants */
#define PERMUT2048_RATE        160
#define PERMUT2048_PAD_BYTE    0x06
#define PERMUT2048_PAD_FINAL   0x80

/* Volume filesystem constants */
#define VFS_MAGIC              0x54534B44  /* "TSKD" */
#define VFS_VERSION            1
#define VFS_MAX_FILES          1024
#define VFS_MAX_FILENAME_LEN   256
#define VFS_SECTOR_SIZE        4096

#define KRAKKEN5_MAGIC         "KRAKKEN5"

/* Per-sector random nonce stored on every write (V5 sector format) */
#define SECTOR_NONCE_SIZE      24

#endif /* CONFIG_H */
