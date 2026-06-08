/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
/* Base58Check decode support for Bitcoin addresses */
#ifndef __BRAINFLAYER_BASE58_H_
#define __BRAINFLAYER_BASE58_H_

#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

/* Base58 alphabet used by Bitcoin */
static const char b58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Map ASCII byte to its Base58 digit value, or -1 if invalid */
static int b58_digit(unsigned char c) {
    const char *p = strchr(b58_alphabet, c);
    if (p == NULL) return -1;
    return (int)(p - b58_alphabet);
}

/*
 * Decode a Base58 string into a fixed-size big-endian byte buffer.
 * out_sz must be exactly the expected decoded byte count (25 for a
 * standard Bitcoin address).
 * Returns 0 on success, -1 on invalid character, -2 on overflow.
 */
static int base58_decode(const char *str, unsigned char *out, size_t out_sz) {
    size_t i, j;
    int digit, carry;

    memset(out, 0, out_sz);

    for (i = 0; str[i] != '\0'; i++) {
        digit = b58_digit((unsigned char)str[i]);
        if (digit < 0) return -1;

        carry = digit;
        for (j = out_sz; j-- > 0; ) {
            carry += 58 * (int)out[j];
            out[j] = (unsigned char)(carry & 0xff);
            carry >>= 8;
        }
        if (carry != 0) return -2; /* overflow */
    }
    return 0;
}

/*
 * Decode a Bitcoin address (Base58Check) and extract the 20-byte hash160.
 * Verifies the 4-byte checksum.
 *
 * addr        - null-terminated address string (e.g. "1A1zP1eP5...")
 * hash160_out - output buffer, must be at least 20 bytes
 *
 * Returns 0 on success, negative on error:
 *   -1  invalid Base58 character
 *   -2  overflow during decode
 *   -3  checksum mismatch
 */
static int base58check_decode_hash160(const char *addr, unsigned char *hash160_out) {
    unsigned char decoded[25]; /* 1-byte version + 20-byte hash160 + 4-byte checksum */
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    int ret;

    ret = base58_decode(addr, decoded, sizeof(decoded));
    if (ret != 0) return ret;

    /* Double-SHA256 of the first 21 bytes (version + hash160) */
    SHA256(decoded, 21, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    /* Verify checksum (last 4 bytes of decoded) */
    if (memcmp(decoded + 21, hash2, 4) != 0) return -3;

    /* Extract hash160 (bytes 1..20) */
    memcpy(hash160_out, decoded + 1, 20);
    return 0;
}

/*
 * Return a human-readable description of a base58check_decode_hash160 error code.
 */
static __attribute__((unused)) const char *base58_strerror(int err) {
    switch (err) {
        case -1: return "invalid Base58 character";
        case -2: return "overflow (address too long)";
        case -3: return "checksum mismatch (invalid address)";
        default: return "unknown error";
    }
}


/*
 * Check whether a string looks like a Bitcoin address.
 * A valid address starts with '1' (P2PKH) or '3' (P2SH),
 * contains only Base58 characters, and has length 25-34.
 * Returns 1 if it looks like an address, 0 otherwise.
 */
static int is_bitcoin_address(const char *s) {
    size_t i, len;
    if (s == NULL) return 0;
    if (s[0] != '1' && s[0] != '3') return 0;
    len = strlen(s);
    if (len < 25 || len > 34) return 0;
    for (i = 0; i < len; i++) {
        if (b58_digit((unsigned char)s[i]) < 0) return 0;
    }
    return 1;
}

#endif /* __BRAINFLAYER_BASE58_H_ */
/*  vim: set ts=2 sw=2 et ai si: */
