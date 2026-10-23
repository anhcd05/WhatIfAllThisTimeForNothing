/*
 * ctfdec.h - bo giai ma "dung ngay" bang C cho Reverse CTF (header-only, C99).
 * Bien dich duoc bang gcc / clang / mingw / MSVC.  Khong can thu vien ngoai.
 *   gcc -O2 -Wall -Wextra -o t test_ctfdec.c
 * Quy uoc: little-endian (x86), mat ma khoi dung ECB.
 */
#ifndef CTFDEC_H
#define CTFDEC_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ---------- xoay bit ---------- */
#define ROL8(x, n)  ((uint8_t)(((x) << (n)) | ((x) >> (8 - (n)))))
#define ROR8(x, n)  ((uint8_t)(((x) >> (n)) | ((x) << (8 - (n)))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* ---------- base64 (alphabet tuy y, 64 ky tu) ---------- */
static inline size_t ctf_b64_decode(const char *in, uint8_t *out, const char *alpha)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (; *in && *in != '='; in++) {
        const char *p = strchr(alpha, *in);
        if (!p) continue;
        acc = (acc << 6) | (uint32_t)(p - alpha);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (uint8_t)(acc >> bits); }
    }
    return o;
}

/* ---------- phep toan don gian (dao nguoc) ---------- */
static inline void ctf_xor_repeat(uint8_t *b, size_t n, const uint8_t *key, size_t kl)
{ for (size_t i = 0; i < n; i++) b[i] ^= key[i % kl]; }
static inline void ctf_undo_add(uint8_t *b, size_t n, uint8_t k) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(b[i] - k); }
static inline void ctf_undo_sub(uint8_t *b, size_t n, uint8_t k) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(b[i] + k); }
static inline void ctf_undo_not(uint8_t *b, size_t n)            { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)~b[i]; }
static inline void ctf_undo_rol8(uint8_t *b, size_t n, int k)    { for (size_t i = 0; i < n; i++) b[i] = ROR8(b[i], k); }
static inline void ctf_undo_ror8(uint8_t *b, size_t n, int k)    { for (size_t i = 0; i < n; i++) b[i] = ROL8(b[i], k); }

/* chuoi: c=b^(0x5A+i); c=rol3(c); c+=0x13; c^=prev  ->  dao nguoc tung buoc */
static inline void ctf_mix_chain_decrypt(uint8_t *b, size_t n)
{
    uint8_t prev = 0x42;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = b[i], t = (uint8_t)(c ^ prev);
        prev = c;
        t = (uint8_t)(t - 0x13);
        t = ROR8(t, 3);
        b[i] = (uint8_t)(t ^ (uint8_t)(0x5A + i));
    }
}

/* ---------- RC4 (ma hoa == giai ma) ---------- */
static inline void ctf_rc4(const uint8_t *key, size_t kl, uint8_t *buf, size_t n)
{
    uint8_t S[256], t;
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + key[i % kl]) & 255; t = S[i]; S[i] = S[j]; S[j] = t; }
    i = j = 0;
    for (size_t k = 0; k < n; k++) {
        i = (i + 1) & 255; j = (j + S[i]) & 255;
        t = S[i]; S[i] = S[j]; S[j] = t;
        buf[k] ^= S[(S[i] + S[j]) & 255];
    }
}

/* ---------- TEA / XTEA / XXTEA (giai ma) ---------- */
#define CTF_DELTA 0x9E3779B9u
static inline void ctf_tea_decrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = CTF_DELTA * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= CTF_DELTA;
    }
    v[0] = v0; v[1] = v1;
}
static inline void ctf_xtea_decrypt(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1], sum = CTF_DELTA * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= CTF_DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}
#define CTF_MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
static inline void ctf_xxtea_decrypt(uint32_t *v, int n, const uint32_t key[4])
{
    uint32_t y, z, sum, e;
    int p, rounds = 6 + 52 / n;
    sum = (uint32_t)rounds * CTF_DELTA;
    y = v[0];
    do {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--) { z = v[p - 1]; y = v[p] -= CTF_MX; }
        z = v[n - 1];
        y = v[0] -= CTF_MX;
        sum -= CTF_DELTA;
    } while (--rounds);
}

/* ---------- AES-128 giai ma (tu sinh S-box luc chay, khong can bang) ---------- */
typedef struct { uint8_t sbox[256], inv[256], rk[176]; } ctf_aes_t;
static inline uint8_t ctf_xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static inline uint8_t ctf_gm(uint8_t a, uint8_t b)
{ uint8_t p = 0; while (b) { if (b & 1) p ^= a; a = ctf_xt(a); b >>= 1; } return p; }

static inline void ctf_aes_init(ctf_aes_t *c, const uint8_t key[16])
{
    uint8_t p = 1, q = 1, rc = 1;
    do {                                   /* sinh S-box bang nghich dao trong GF(2^8) */
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0));
        q ^= (uint8_t)(q << 1); q ^= (uint8_t)(q << 2); q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        c->sbox[p] = (uint8_t)(q ^ ROL8(q, 1) ^ ROL8(q, 2) ^ ROL8(q, 3) ^ ROL8(q, 4) ^ 0x63);
    } while (p != 1);
    c->sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) c->inv[c->sbox[i]] = (uint8_t)i;
    memcpy(c->rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, c->rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t u = t[0];
            t[0] = c->sbox[t[1]] ^ rc; t[1] = c->sbox[t[2]]; t[2] = c->sbox[t[3]]; t[3] = c->sbox[u];
            rc = ctf_xt(rc);
        }
        for (int j = 0; j < 4; j++) c->rk[i + j] = c->rk[i + j - 16] ^ t[j];
    }
}

static inline void ctf_aes_decrypt_block(const ctf_aes_t *c, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ c->rk[160 + i];
    for (int r = 9; r >= 0; r--) {
        for (int col = 0; col < 4; col++)
            for (int rr = 0; rr < 4; rr++)
                t[col * 4 + rr] = c->inv[s[((col - rr + 4) & 3) * 4 + rr]];
        for (int i = 0; i < 16; i++) t[i] ^= c->rk[r * 16 + i];
        if (r > 0) {
            for (int col = 0; col < 4; col++) {
                uint8_t a0 = t[col * 4], a1 = t[col * 4 + 1], a2 = t[col * 4 + 2], a3 = t[col * 4 + 3];
                s[col * 4 + 0] = (uint8_t)(ctf_gm(a0, 14) ^ ctf_gm(a1, 11) ^ ctf_gm(a2, 13) ^ ctf_gm(a3, 9));
                s[col * 4 + 1] = (uint8_t)(ctf_gm(a0, 9) ^ ctf_gm(a1, 14) ^ ctf_gm(a2, 11) ^ ctf_gm(a3, 13));
                s[col * 4 + 2] = (uint8_t)(ctf_gm(a0, 13) ^ ctf_gm(a1, 9) ^ ctf_gm(a2, 14) ^ ctf_gm(a3, 11));
                s[col * 4 + 3] = (uint8_t)(ctf_gm(a0, 11) ^ ctf_gm(a1, 13) ^ ctf_gm(a2, 9) ^ ctf_gm(a3, 14));
            }
        } else memcpy(s, t, 16);
    }
    memcpy(out, s, 16);
}

/* ---------- ChaCha20 / Salsa20 (XOR keystream, dem = 0) ---------- */
#define CTF_QR(a, b, c, d) a += b; d ^= a; d = ROL32(d, 16); c += d; b ^= c; b = ROL32(b, 12); \
                           a += b; d ^= a; d = ROL32(d, 8);  c += d; b ^= c; b = ROL32(b, 7);
static inline void ctf_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t n)
{
    uint32_t base[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}, x[16];
    memcpy(base + 4, key, 32);
    memcpy(base + 13, nonce, 12);
    for (size_t off = 0; off < n; off += 64) {
        uint8_t ks[64];
        base[12] = (uint32_t)(off / 64);
        memcpy(x, base, 64);
        for (int i = 0; i < 10; i++) {
            CTF_QR(x[0], x[4], x[8], x[12]) CTF_QR(x[1], x[5], x[9], x[13])
            CTF_QR(x[2], x[6], x[10], x[14]) CTF_QR(x[3], x[7], x[11], x[15])
            CTF_QR(x[0], x[5], x[10], x[15]) CTF_QR(x[1], x[6], x[11], x[12])
            CTF_QR(x[2], x[7], x[8], x[13]) CTF_QR(x[3], x[4], x[9], x[14])
        }
        for (int i = 0; i < 16; i++) { uint32_t v = x[i] + base[i]; memcpy(ks + 4 * i, &v, 4); }
        for (size_t i = 0; i < 64 && off + i < n; i++) buf[off + i] ^= ks[i];
    }
}

static inline void ctf_salsa20_xor(const uint8_t key[32], const uint8_t nonce[8], uint8_t *buf, size_t n)
{
    uint32_t s[16], x[16], k[8], nn[2];
    memcpy(k, key, 32); memcpy(nn, nonce, 8);
    for (size_t off = 0; off < n; off += 64) {
        uint8_t ks[64];
        uint64_t ctr = off / 64;
        s[0] = 0x61707865; s[5] = 0x3320646e; s[10] = 0x79622d32; s[15] = 0x6b206574;
        for (int i = 0; i < 4; i++) { s[1 + i] = k[i]; s[11 + i] = k[4 + i]; }
        s[6] = nn[0]; s[7] = nn[1]; s[8] = (uint32_t)ctr; s[9] = (uint32_t)(ctr >> 32);
        memcpy(x, s, 64);
        for (int i = 0; i < 10; i++) {
            x[4] ^= ROL32(x[0] + x[12], 7);  x[8] ^= ROL32(x[4] + x[0], 9);
            x[12] ^= ROL32(x[8] + x[4], 13); x[0] ^= ROL32(x[12] + x[8], 18);
            x[9] ^= ROL32(x[5] + x[1], 7);   x[13] ^= ROL32(x[9] + x[5], 9);
            x[1] ^= ROL32(x[13] + x[9], 13); x[5] ^= ROL32(x[1] + x[13], 18);
            x[14] ^= ROL32(x[10] + x[6], 7); x[2] ^= ROL32(x[14] + x[10], 9);
            x[6] ^= ROL32(x[2] + x[14], 13); x[10] ^= ROL32(x[6] + x[2], 18);
            x[3] ^= ROL32(x[15] + x[11], 7); x[7] ^= ROL32(x[3] + x[15], 9);
            x[11] ^= ROL32(x[7] + x[3], 13); x[15] ^= ROL32(x[11] + x[7], 18);
            x[1] ^= ROL32(x[0] + x[3], 7);   x[2] ^= ROL32(x[1] + x[0], 9);
            x[3] ^= ROL32(x[2] + x[1], 13);  x[0] ^= ROL32(x[3] + x[2], 18);
            x[6] ^= ROL32(x[5] + x[4], 7);   x[7] ^= ROL32(x[6] + x[5], 9);
            x[4] ^= ROL32(x[7] + x[6], 13);  x[5] ^= ROL32(x[4] + x[7], 18);
            x[11] ^= ROL32(x[10] + x[9], 7); x[8] ^= ROL32(x[11] + x[10], 9);
            x[9] ^= ROL32(x[8] + x[11], 13); x[10] ^= ROL32(x[9] + x[8], 18);
            x[12] ^= ROL32(x[15] + x[14], 7); x[13] ^= ROL32(x[12] + x[15], 9);
            x[14] ^= ROL32(x[13] + x[12], 13); x[15] ^= ROL32(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++) { uint32_t v = x[i] + s[i]; memcpy(ks + 4 * i, &v, 4); }
        for (size_t i = 0; i < 64 && off + i < n; i++) buf[off + i] ^= ks[i];
    }
}

/* ---------- hash/checksum: tinh + quay lui 1 buoc ---------- */
static inline uint32_t ctf_crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}
/* nghich dao modulo 2^32 cua so le a (Newton: moi vong gap doi so bit dung) */
static inline uint32_t ctf_inv32(uint32_t a)
{ uint32_t x = a; for (int i = 0; i < 5; i++) x *= 2 - a * x; return x; }
static inline uint32_t ctf_fnv1a_unstep(uint32_t h, uint8_t c) { return (h * ctf_inv32(16777619u)) ^ c; }
static inline uint32_t ctf_djb2_unstep(uint32_t h, uint8_t c)  { return (h - c) * ctf_inv32(33u); }

#endif /* CTFDEC_H */

