/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h> /*  for ntohl/htonl */

#include <math.h> /* pow/exp */

#include "hex.h"
#include "bloom.h"
#include "hash160.h"
#include "base58.h"

const double k_hashes = 25;
const double m_bits   = 4294967296*2;

/* Check whether a string is exactly 40 lowercase hex characters. */
static int is_hex_hash160(const char *s) {
  size_t i, len = strlen(s);
  if (len != 40) return 0;
  for (i = 0; i < 40; i++) {
    if (!isxdigit((unsigned char)s[i])) return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  hash160_t hash;
  int i;
  double pct;
  struct stat sb;
  unsigned char *bloom, *hashfile, *bloomfile;
  FILE *f, *b;
  size_t line_sz = 1024, line_ct = 0, skip_ct = 0;
  char *line, *trimmed;

  double err_rate;

  if (argc != 3) {
    fprintf(stderr, "[!] Usage: %s hashfile.hex bloomfile.blf\n", argv[0]);
    fprintf(stderr, "    The input file may contain hex hash160 values (40 hex chars)\n");
    fprintf(stderr, "    and/or Bitcoin addresses (P2PKH starting with '1' or P2SH with '3').\n");
    exit(1);
  }

  hashfile = argv[1];
  bloomfile = argv[2];

  if ((f = fopen(hashfile, "r")) == NULL) {
    fprintf(stderr, "[!] Failed to open hash160 file '%s'\n", hashfile);
    exit(1);
  }

  if ((bloom = malloc(BLOOM_SIZE)) == NULL) {
    fprintf(stderr, "[!] malloc failed (bloom filter)\n");
    exit(1);
  }

  if (stat(bloomfile, &sb) == 0) {
    if (!S_ISREG(sb.st_mode) || sb.st_size != BLOOM_SIZE) {
      fprintf(stderr, "[!] Bloom filter file '%s' is not the correct size (%ju != %d)\n", bloomfile, sb.st_size, BLOOM_SIZE);
      exit(1);
    }
    if ((b = fopen(bloomfile, "r+")) == NULL) {
      fprintf(stderr, "[!] Failed to open bloom filter file '%s' for read/write\n", bloomfile);
      exit(1);
    }
    fprintf(stderr, "[*] Reading existing bloom filter from '%s'...\n", bloomfile);
    if ((fread(bloom, BLOOM_SIZE, 1, b)) != 1 || (fseek(b, 0, SEEK_SET)) != 0) {
      fprintf(stderr, "[!] Failed to read existing boom filter from '%s'\n", bloomfile);
      exit(1);
    }
  } else {
    /*  Assume the file didn't exist - yes there is a race condition */
    if ((b = fopen(bloomfile, "w+")) == NULL) {
      fprintf(stderr, "[!] Failed to create bloom filter file '%s'\n", bloomfile);
      exit(1);
    }
    /* start it empty */
    fprintf(stderr, "[*] Initializing bloom filter...\n");
    memset(bloom, 0, BLOOM_SIZE);
  }

  if ((line = malloc(line_sz+1)) == NULL) {
    fprintf(stderr, "[!] malloc failed (line buffer)\n");
    exit(1);
  }

  i = 0;
  stat(hashfile, &sb);
  fprintf(stderr, "[*] Loading hashes/addresses from '%s' \033[s  0.0%%", hashfile);
  while (getline(&line, &line_sz, f) > 0) {
    /* Strip trailing whitespace (newline, CR, spaces) */
    trimmed = line;
    size_t tlen = strlen(trimmed);
    while (tlen > 0 && (trimmed[tlen-1] == '\n' || trimmed[tlen-1] == '\r' ||
                        trimmed[tlen-1] == ' '  || trimmed[tlen-1] == '\t')) {
      trimmed[--tlen] = '\0';
    }
    if (tlen == 0) continue; /* blank line */

    if (is_hex_hash160(trimmed)) {
      /* Hex-encoded hash160 (existing behaviour) */
      unhex((unsigned char *)trimmed, tlen, hash.uc, sizeof(hash.uc));
      bloom_set_hash160(bloom, hash.ul);
      ++line_ct;
    } else if (is_bitcoin_address(trimmed)) {
      /* Bitcoin address: decode Base58Check, extract hash160 */
      int ret = base58check_decode_hash160(trimmed, hash.uc);
      if (ret == 0) {
        bloom_set_hash160(bloom, hash.ul);
        ++line_ct;
      } else {
        ++skip_ct;
      }
    } else {
      ++skip_ct;
    }

    if ((++i & 0x3ffff) == 0) {
      pct = 100.0 * ftell(f) / sb.st_size;
      fprintf(stderr, "\033[u%5.1f%%", pct);
      fflush(stderr);
    }
  }
  fprintf(stderr, "\033[u 100.0%%\n");

  err_rate = pow(1 - exp(-k_hashes * line_ct / m_bits), k_hashes);
  fprintf(stderr, "[*] Loaded %zu hashes/addresses", line_ct);
  if (skip_ct > 0) fprintf(stderr, ", skipped %zu invalid lines", skip_ct);
  fprintf(stderr, ", false positive rate: ~%.3e (1 in ~%.3e)\n", err_rate, 1/err_rate);

  fprintf(stderr, "[*] Writing bloom filter to '%s'...\n", bloomfile);
  if ((fwrite(bloom, BLOOM_SIZE, 1, b)) != 1) {
    fprintf(stderr, "[!] Failed to write bloom filter file '%s'\n", bloomfile);
    exit(1);
  }

  fprintf(stderr, "[+] Success!\n");
  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
