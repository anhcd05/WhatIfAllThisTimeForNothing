/*
 * algos.c - phong thi nghiem: moi thuat toan encode/crypto/hash la 1 ham rieng (noinline)
 * de dem vao IDA doc ma gia. KHONG dung thu vien ngoai (tu cai dat), tru bang hang so trong tables.h.
 * Dung: algos [input]   (input <= 200 byte)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "tables.h"

#if defined(_MSC_VER)
#define NOINL __declspec(noinline)
#else
#define NOINL __attribute__((noinline))
#endif

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* =========================== ENCODE =========================== */

NOINL size_t b64_encode(const uint8_t *in, size_t n, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = T[v >> 18];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
        out[o++] = T[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = T[v >> 18];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = T[v >> 18];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = 0;
    return o;
}

NOINL size_t b64_decode(const char *in, uint8_t *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (; *in && *in != '='; in++) {
        const char *p = strchr(T, *in);
        if (!p) continue;
        acc = (acc << 6) | (uint32_t)(p - T);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

NOINL size_t b32_encode(const uint8_t *in, size_t n, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t o = 0;
    uint64_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o++] = T[(acc >> bits) & 31];
        }
    }
    if (bits > 0) out[o++] = T[(acc << (5 - bits)) & 31];
    while (o % 8) out[o++] = '=';
    out[o] = 0;
    return o;
}

NOINL size_t b58_encode(const uint8_t *in, size_t n, char *out)
{
    static const char T[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t buf[300];
    size_t zeros = 0, len = 0, o = 0;
    memset(buf, 0, sizeof(buf));
    while (zeros < n && in[zeros] == 0) zeros++;
    for (size_t i = zeros; i < n; i++) {
        int carry = in[i];
        for (size_t j = 0; j < len; j++) {
            carry += buf[j] * 256;
            buf[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry) {
            buf[len++] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (size_t i = len; i > 0; i--) out[o++] = T[buf[i - 1]];
    out[o] = 0;
    return o;
}

NOINL size_t a85_encode(const uint8_t *in, size_t n, char *out)
{
    size_t o = 0, i = 0;
    for (; i + 4 <= n; i += 4) {
        uint32_t v = ((uint32_t)in[i] << 24) | ((uint32_t)in[i + 1] << 16) |
                     ((uint32_t)in[i + 2] << 8) | in[i + 3];
        if (v == 0) {
            out[o++] = 'z';
            continue;
        }
        char t[5];
        for (int k = 4; k >= 0; k--) {
            t[k] = (char)(v % 85 + 33);
            v /= 85;
        }
        memcpy(out + o, t, 5);
        o += 5;
    }
    if (i < n) {
        uint8_t b[4] = {0, 0, 0, 0};
        size_t r = n - i;
        memcpy(b, in + i, r);
        uint32_t v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        char t[5];
        for (int k = 4; k >= 0; k--) {
            t[k] = (char)(v % 85 + 33);
            v /= 85;
        }
        memcpy(out + o, t, r + 1);
        o += r + 1;
    }
    out[o] = 0;
    return o;
}

NOINL size_t hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[in[i] >> 4];
        out[2 * i + 1] = H[in[i] & 15];
    }
    out[2 * n] = 0;
    return 2 * n;
}

/* ============== phep toan don gian hay gap trong check flag ============== */

NOINL void rot13(char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'a' && c <= 'z') s[i] = (char)((c - 'a' + 13) % 26 + 'a');
        else if (c >= 'A' && c <= 'Z') s[i] = (char)((c - 'A' + 13) % 26 + 'A');
    }
}

NOINL void xor_single(uint8_t *b, size_t n, uint8_t k)
{
    for (size_t i = 0; i < n; i++) b[i] ^= k;
}

NOINL void xor_repeat(uint8_t *b, size_t n, const uint8_t *key, size_t kl)
{
    for (size_t i = 0; i < n; i++) b[i] ^= key[i % kl];
}

NOINL void op_add(uint8_t *b, size_t n, uint8_t k)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(b[i] + k);
}

NOINL void op_sub(uint8_t *b, size_t n, uint8_t k)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(b[i] - k);
}

NOINL void op_not(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)~b[i];
}

NOINL void op_rol8(uint8_t *b, size_t n, int k)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)((b[i] << k) | (b[i] >> (8 - k)));
}

NOINL void op_ror8(uint8_t *b, size_t n, int k)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)((b[i] >> k) | (b[i] << (8 - k)));
}

NOINL uint32_t op_rol32(uint32_t x, int k) { return ROL32(x, k); }
NOINL uint32_t op_ror32(uint32_t x, int k) { return ROR32(x, k); }

NOINL void op_reverse(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n / 2; i++) {
        uint8_t t = b[i];
        b[i] = b[n - 1 - i];
        b[n - 1 - i] = t;
    }
}

/* chuoi bien doi kieu check flag: xor index -> rol -> cong hang -> xor chain */
NOINL void mix_chain(uint8_t *b, size_t n)
{
    uint8_t prev = 0x42;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = (uint8_t)(b[i] ^ (0x5A + i));
        c = (uint8_t)((c << 3) | (c >> 5));
        c = (uint8_t)(c + 0x13);
        c ^= prev;
        prev = c;
        b[i] = c;
    }
}

/* ======================== SYMMETRIC CIPHERS ======================== */

NOINL void rc4_crypt(const uint8_t *key, size_t kl, uint8_t *buf, size_t n)
{
    uint8_t S[256], t;
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % kl]) & 255;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = 0; j = 0;
    for (size_t k = 0; k < n; k++) {
        i = (i + 1) & 255;
        j = (j + S[i]) & 255;
        t = S[i]; S[i] = S[j]; S[j] = t;
        buf[k] ^= S[(S[i] + S[j]) & 255];
    }
}

NOINL void tea_encrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}

NOINL void tea_decrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}

NOINL void xtea_encrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

NOINL void xtea_decrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

NOINL void xxtea_encrypt(uint32_t *v, int n, const uint32_t key[4])
{
    uint32_t y, z, sum = 0, e, delta = 0x9E3779B9;
    int p, rounds = 6 + 52 / n;
    z = v[n - 1];
    while (rounds-- > 0) {
        sum += delta;
        e = (sum >> 2) & 3;
        for (p = 0; p < n - 1; p++) {
            y = v[p + 1];
            z = v[p] += MX;
        }
        y = v[0];
        z = v[n - 1] += MX;
    }
}

NOINL void xxtea_decrypt(uint32_t *v, int n, const uint32_t key[4])
{
    uint32_t y, z, sum, e, delta = 0x9E3779B9;
    int p, rounds = 6 + 52 / n;
    sum = (uint32_t)rounds * delta;
    y = v[0];
    do {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--) {
            z = v[p - 1];
            y = v[p] -= MX;
        }
        z = v[n - 1];
        y = v[0] -= MX;
        sum -= delta;
    } while (--rounds);
}

static uint8_t xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static uint8_t gm(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        a = xt(a);
        b >>= 1;
    }
    return p;
}

NOINL void aes128_key_expand(const uint8_t key[16], uint8_t rk[176])
{
    uint8_t rc = 1;
    memcpy(rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = AES_SBOX[t[1]] ^ rc;
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[u];
            rc = xt(rc);
        }
        for (int j = 0; j < 4; j++) rk[i + j] = rk[i + j - 16] ^ t[j];
    }
}

NOINL void aes128_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 1; r <= 10; r++) {
        for (int c = 0; c < 4; c++)
            for (int rr = 0; rr < 4; rr++)
                t[c * 4 + rr] = AES_SBOX[s[((c + rr) & 3) * 4 + rr]];
        if (r < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3];
                s[c * 4 + 0] = (uint8_t)(xt(a0) ^ (xt(a1) ^ a1) ^ a2 ^ a3);
                s[c * 4 + 1] = (uint8_t)(a0 ^ xt(a1) ^ (xt(a2) ^ a2) ^ a3);
                s[c * 4 + 2] = (uint8_t)(a0 ^ a1 ^ xt(a2) ^ (xt(a3) ^ a3));
                s[c * 4 + 3] = (uint8_t)((xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3));
            }
        } else {
            memcpy(s, t, 16);
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    memcpy(out, s, 16);
}

NOINL void aes128_decrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[160 + i];
    for (int r = 9; r >= 0; r--) {
        for (int c = 0; c < 4; c++)
            for (int rr = 0; rr < 4; rr++)
                t[c * 4 + rr] = AES_INV_SBOX[s[((c - rr + 4) & 3) * 4 + rr]];
        for (int i = 0; i < 16; i++) t[i] ^= rk[r * 16 + i];
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3];
                s[c * 4 + 0] = (uint8_t)(gm(a0, 14) ^ gm(a1, 11) ^ gm(a2, 13) ^ gm(a3, 9));
                s[c * 4 + 1] = (uint8_t)(gm(a0, 9) ^ gm(a1, 14) ^ gm(a2, 11) ^ gm(a3, 13));
                s[c * 4 + 2] = (uint8_t)(gm(a0, 13) ^ gm(a1, 9) ^ gm(a2, 14) ^ gm(a3, 11));
                s[c * 4 + 3] = (uint8_t)(gm(a0, 11) ^ gm(a1, 13) ^ gm(a2, 9) ^ gm(a3, 14));
            }
        } else {
            memcpy(s, t, 16);
        }
    }
    memcpy(out, s, 16);
}

#define CC_QR(a, b, c, d)                                              \
    a += b; d ^= a; d = ROL32(d, 16);                                  \
    c += d; b ^= c; b = ROL32(b, 12);                                  \
    a += b; d ^= a; d = ROL32(d, 8);                                   \
    c += d; b ^= c; b = ROL32(b, 7);

NOINL void chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint8_t out[64])
{
    uint32_t s[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t x[16];
    for (int i = 0; i < 8; i++) s[4 + i] = key[i];
    s[12] = counter;
    s[13] = nonce[0]; s[14] = nonce[1]; s[15] = nonce[2];
    memcpy(x, s, sizeof(x));
    for (int i = 0; i < 10; i++) {
        CC_QR(x[0], x[4], x[8], x[12])
        CC_QR(x[1], x[5], x[9], x[13])
        CC_QR(x[2], x[6], x[10], x[14])
        CC_QR(x[3], x[7], x[11], x[15])
        CC_QR(x[0], x[5], x[10], x[15])
        CC_QR(x[1], x[6], x[11], x[12])
        CC_QR(x[2], x[7], x[8], x[13])
        CC_QR(x[3], x[4], x[9], x[14])
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        memcpy(out + 4 * i, &v, 4);
    }
}

NOINL void chacha20_xor(const uint32_t key[8], const uint32_t nonce[3], uint8_t *buf, size_t n)
{
    uint8_t ks[64];
    uint32_t ctr = 0;
    for (size_t off = 0; off < n; off += 64, ctr++) {
        chacha20_block(key, ctr, nonce, ks);
        for (size_t i = 0; i < 64 && off + i < n; i++) buf[off + i] ^= ks[i];
    }
}

NOINL void salsa20_block(const uint32_t key[8], const uint32_t nonce[2], uint64_t counter, uint8_t out[64])
{
    uint32_t s[16], x[16];
    s[0] = 0x61707865; s[5] = 0x3320646e; s[10] = 0x79622d32; s[15] = 0x6b206574;
    for (int i = 0; i < 4; i++) { s[1 + i] = key[i]; s[11 + i] = key[4 + i]; }
    s[6] = nonce[0]; s[7] = nonce[1];
    s[8] = (uint32_t)counter; s[9] = (uint32_t)(counter >> 32);
    memcpy(x, s, sizeof(x));
    for (int i = 0; i < 10; i++) {
        x[ 4] ^= ROL32(x[ 0] + x[12],  7); x[ 8] ^= ROL32(x[ 4] + x[ 0],  9);
        x[12] ^= ROL32(x[ 8] + x[ 4], 13); x[ 0] ^= ROL32(x[12] + x[ 8], 18);
        x[ 9] ^= ROL32(x[ 5] + x[ 1],  7); x[13] ^= ROL32(x[ 9] + x[ 5],  9);
        x[ 1] ^= ROL32(x[13] + x[ 9], 13); x[ 5] ^= ROL32(x[ 1] + x[13], 18);
        x[14] ^= ROL32(x[10] + x[ 6],  7); x[ 2] ^= ROL32(x[14] + x[10],  9);
        x[ 6] ^= ROL32(x[ 2] + x[14], 13); x[10] ^= ROL32(x[ 6] + x[ 2], 18);
        x[ 3] ^= ROL32(x[15] + x[11],  7); x[ 7] ^= ROL32(x[ 3] + x[15],  9);
        x[11] ^= ROL32(x[ 7] + x[ 3], 13); x[15] ^= ROL32(x[11] + x[ 7], 18);
        x[ 1] ^= ROL32(x[ 0] + x[ 3],  7); x[ 2] ^= ROL32(x[ 1] + x[ 0],  9);
        x[ 3] ^= ROL32(x[ 2] + x[ 1], 13); x[ 0] ^= ROL32(x[ 3] + x[ 2], 18);
        x[ 6] ^= ROL32(x[ 5] + x[ 4],  7); x[ 7] ^= ROL32(x[ 6] + x[ 5],  9);
        x[ 4] ^= ROL32(x[ 7] + x[ 6], 13); x[ 5] ^= ROL32(x[ 4] + x[ 7], 18);
        x[11] ^= ROL32(x[10] + x[ 9],  7); x[ 8] ^= ROL32(x[11] + x[10],  9);
        x[ 9] ^= ROL32(x[ 8] + x[11], 13); x[10] ^= ROL32(x[ 9] + x[ 8], 18);
        x[12] ^= ROL32(x[15] + x[14],  7); x[13] ^= ROL32(x[12] + x[15],  9);
        x[14] ^= ROL32(x[13] + x[12], 13); x[15] ^= ROL32(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        memcpy(out + 4 * i, &v, 4);
    }
}

NOINL void salsa20_xor(const uint32_t key[8], const uint32_t nonce[2], uint8_t *buf, size_t n)
{
    uint8_t ks[64];
    uint64_t ctr = 0;
    for (size_t off = 0; off < n; off += 64, ctr++) {
        salsa20_block(key, nonce, ctr, ks);
        for (size_t i = 0; i < 64 && off + i < n; i++) buf[off + i] ^= ks[i];
    }
}

/* ============================== HASH ============================== */

NOINL void md5_hash(const uint8_t *msg, size_t n, uint8_t out[16])
{
    static const int R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint8_t buf[320];
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    size_t total = ((n + 8) / 64 + 1) * 64;
    uint64_t bits = (uint64_t)n * 8;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg, n);
    buf[n] = 0x80;
    memcpy(buf + total - 8, &bits, 8);
    for (size_t off = 0; off < total; off += 64) {
        uint32_t M[16], A = a0, B = b0, C = c0, D = d0;
        memcpy(M, buf + off, 64);
        for (int i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16)      { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) & 15; }
            else             { F = C ^ (B | ~D);       g = (7 * i) & 15; }
            F = F + A + MD5_K[i] + M[g];
            A = D; D = C; C = B;
            B = B + ROL32(F, R[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    memcpy(out, &a0, 4); memcpy(out + 4, &b0, 4);
    memcpy(out + 8, &c0, 4); memcpy(out + 12, &d0, 4);
}

NOINL void sha1_hash(const uint8_t *msg, size_t n, uint8_t out[20])
{
    uint8_t buf[320];
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    size_t total = ((n + 8) / 64 + 1) * 64;
    uint64_t bits = (uint64_t)n * 8;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg, n);
    buf[n] = 0x80;
    for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off + 4 * i] << 24) | ((uint32_t)buf[off + 4 * i + 1] << 16) |
                   ((uint32_t)buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3];
        for (int i = 16; i < 80; i++) w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            uint32_t tmp = ROL32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = ROL32(b, 30); b = a; a = tmp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    uint32_t h[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}

NOINL void sha256_hash(const uint8_t *msg, size_t n, uint8_t out[32])
{
    uint8_t buf[320];
    uint32_t H[8];
    size_t total = ((n + 8) / 64 + 1) * 64;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) H[i] = SHA256_H0[i];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg, n);
    buf[n] = 0x80;
    for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off + 4 * i] << 24) | ((uint32_t)buf[off + 4 * i + 1] << 16) |
                   ((uint32_t)buf[off + 4 * i + 2] << 8) | buf[off + 4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(H[i] >> 24); out[4 * i + 1] = (uint8_t)(H[i] >> 16);
        out[4 * i + 2] = (uint8_t)(H[i] >> 8); out[4 * i + 3] = (uint8_t)H[i];
    }
}

NOINL void sha512_hash(const uint8_t *msg, size_t n, uint8_t out[64])
{
    uint8_t buf[384];
    uint64_t H[8];
    size_t total = ((n + 16) / 128 + 1) * 128;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) H[i] = SHA512_H0[i];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, msg, n);
    buf[n] = 0x80;
    for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 128) {
        uint64_t w[80];
        for (int i = 0; i < 16; i++) {
            uint64_t v = 0;
            for (int j = 0; j < 8; j++) v = (v << 8) | buf[off + 8 * i + j];
            w[i] = v;
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = h + S1 + ch + SHA512_K[i] + w[i];
            uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(H[i] >> (56 - 8 * j));
}

NOINL uint32_t crc32_table(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = CRC32_TAB[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

NOINL uint32_t crc32_bitwise(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

NOINL uint32_t adler32_hash(const uint8_t *p, size_t n)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + p[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

NOINL uint32_t fnv1a_hash(const uint8_t *p, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

NOINL uint32_t djb2_hash(const uint8_t *p, size_t n)
{
    uint32_t h = 5381;
    for (size_t i = 0; i < n; i++) h = h * 33 + p[i];
    return h;
}

/* ============================== MAIN ============================== */

static void ph(const char *tag, const uint8_t *p, size_t n)
{
    printf("%s: ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

static size_t pad_to(const uint8_t *in, size_t n, size_t bs, uint8_t *out)
{
    size_t m = (n + bs - 1) / bs * bs;
    if (!m) m = bs;
    memset(out, 0, 320);
    memcpy(out, in, n);
    return m;
}

int main(int argc, char **argv)
{
    const char *input = argc > 1 ? argv[1] : "Hello, CyberSeaGame!";
    size_t n = strlen(input);
    uint8_t in[256], w[320], pt[320], ct[320], dec[320];
    char s[1024];
    uint8_t d64[64];
    if (n > 200) n = 200;
    memcpy(in, input, n);
    printf("input: %.*s\n", (int)n, input);

    /* --- encode --- */
    b64_encode(in, n, s);                      printf("base64: %s\n", s);
    size_t dl = b64_decode(s, w);              printf("base64_dec: %.*s\n", (int)dl, (char *)w);
    b32_encode(in, n, s);                      printf("base32: %s\n", s);
    b58_encode(in, n, s);                      printf("base58: %s\n", s);
    a85_encode(in, n, s);                      printf("ascii85: %s\n", s);
    hex_encode(in, n, s);                      printf("hex: %s\n", s);

    /* --- phep toan don gian --- */
    memcpy(w, in, n); rot13((char *)w, n);                   ph("rot13", w, n);
    memcpy(w, in, n); xor_single(w, n, 0x5A);                ph("xor_single_5a", w, n);
    memcpy(w, in, n); xor_repeat(w, n, (const uint8_t *)"KEY", 3); ph("xor_repeat_KEY", w, n);
    memcpy(w, in, n); op_add(w, n, 7);                       ph("add_7", w, n);
    memcpy(w, in, n); op_sub(w, n, 7);                       ph("sub_7", w, n);
    memcpy(w, in, n); op_not(w, n);                          ph("not", w, n);
    memcpy(w, in, n); op_rol8(w, n, 3);                      ph("rol8_3", w, n);
    memcpy(w, in, n); op_ror8(w, n, 3);                      ph("ror8_3", w, n);
    printf("rol32: %08x ror32: %08x\n", op_rol32(0x12345678u, 8), op_ror32(0x12345678u, 8));
    memcpy(w, in, n); op_reverse(w, n);                      ph("reverse", w, n);
    memcpy(w, in, n); mix_chain(w, n);                       ph("mix_chain", w, n);

    /* --- symmetric --- */
    memcpy(w, in, n); rc4_crypt((const uint8_t *)"CyberSea", 8, w, n);  ph("rc4_CyberSea", w, n);

    static const uint32_t tk[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    size_t m = pad_to(in, n, 8, pt);
    memcpy(ct, pt, m);
    for (size_t i = 0; i < m; i += 8) { uint32_t v[2]; memcpy(v, ct + i, 8); tea_encrypt(v, tk); memcpy(ct + i, v, 8); }
    ph("tea_ecb", ct, m);
    memcpy(dec, ct, m);
    for (size_t i = 0; i < m; i += 8) { uint32_t v[2]; memcpy(v, dec + i, 8); tea_decrypt(v, tk); memcpy(dec + i, v, 8); }
    printf("tea_dec_ok: %d\n", memcmp(dec, pt, m) == 0);

    memcpy(ct, pt, m);
    for (size_t i = 0; i < m; i += 8) { uint32_t v[2]; memcpy(v, ct + i, 8); xtea_encrypt(v, tk); memcpy(ct + i, v, 8); }
    ph("xtea_ecb", ct, m);
    memcpy(dec, ct, m);
    for (size_t i = 0; i < m; i += 8) { uint32_t v[2]; memcpy(v, dec + i, 8); xtea_decrypt(v, tk); memcpy(dec + i, v, 8); }
    printf("xtea_dec_ok: %d\n", memcmp(dec, pt, m) == 0);

    {
        uint32_t xw[64];
        int xn = (int)(m / 4);
        memcpy(xw, pt, m);
        xxtea_encrypt(xw, xn, tk);
        ph("xxtea", (const uint8_t *)xw, m);
        xxtea_decrypt(xw, xn, tk);
        printf("xxtea_dec_ok: %d\n", memcmp(xw, pt, m) == 0);
    }

    {
        uint8_t rk[176];
        aes128_key_expand((const uint8_t *)"0123456789abcdef", rk);
        m = pad_to(in, n, 16, pt);
        memcpy(ct, pt, m);
        for (size_t i = 0; i < m; i += 16) aes128_encrypt_block(rk, pt + i, ct + i);
        ph("aes128_ecb", ct, m);
        for (size_t i = 0; i < m; i += 16) aes128_decrypt_block(rk, ct + i, dec + i);
        printf("aes_dec_ok: %d\n", memcmp(dec, pt, m) == 0);
    }

    {
        uint32_t ckey[8], cnonce[3] = {0x03020100u, 0x07060504u, 0x0b0a0908u};
        uint32_t snonce[2] = {0x03020100u, 0x07060504u};
        for (int i = 0; i < 8; i++) {
            ckey[i] = (uint32_t)(4 * i) | ((uint32_t)(4 * i + 1) << 8) | ((uint32_t)(4 * i + 2) << 16) | ((uint32_t)(4 * i + 3) << 24);
        }
        memcpy(w, in, n); chacha20_xor(ckey, cnonce, w, n); ph("chacha20", w, n);
        memcpy(w, in, n); salsa20_xor(ckey, snonce, w, n);  ph("salsa20", w, n);
    }

    /* --- hash --- */
    md5_hash(in, n, d64);    ph("md5", d64, 16);
    sha1_hash(in, n, d64);   ph("sha1", d64, 20);
    sha256_hash(in, n, d64); ph("sha256", d64, 32);
    sha512_hash(in, n, d64); ph("sha512", d64, 64);
    printf("crc32_table: %08x\n", crc32_table(in, n));
    printf("crc32_bitwise: %08x\n", crc32_bitwise(in, n));
    printf("adler32: %08x\n", adler32_hash(in, n));
    printf("fnv1a: %08x\n", fnv1a_hash(in, n));
    printf("djb2: %08x\n", djb2_hash(in, n));
    return 0;
}
