/* =============================================================================
 *  brute_sha1.c  —  Brute-force tìm chuỗi có SHA-1 trùng hash cho trước.
 *  ĐI THI CHỈ SỬA 3 DÒNG trong phần CẤU HÌNH. Không phụ thuộc thư viện ngoài.
 *
 *  Biên dịch:  gcc -O2 brute_sha1.c -o brute_sha1
 *  Chạy:       ./brute_sha1
 * ============================================================================= */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "24d999353fdc5f4be32871022973a6253bc21d1b"  /* sha1("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 20                 /* SHA-1 = 20 byte (hex dài 40)           */
#if LEN > 55
#error "Ban 1-block: LEN phai <= 55."
#endif

#define ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

/* ---------- PHẦN 1: SHA-1 (hộp đen). Lưu ý: SHA dùng BIG-ENDIAN. ----------- */
void hash(const unsigned char *msg, size_t len, unsigned char *out) {
    /* Padding: message + 0x80 + 0x00... + độ dài-bit 8 byte BIG-endian. */
    unsigned char block[64];
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[63 - i] = (unsigned char)(bits >> (8 * i));

    /* 16 word big-endian, rồi mở rộng thành 80 word. */
    uint32_t W[80];
    for (int i = 0; i < 16; i++)
        W[i] = (uint32_t)block[4*i] << 24 | block[4*i+1] << 16 | block[4*i+2] << 8 | block[4*i+3];
    for (int i = 16; i < 80; i++)
        W[i] = ROTL32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

    uint32_t h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
    uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if      (i < 20) { f = (b & c) | (~b & d);            k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        uint32_t tmp = ROTL32(a, 5) + f + e + k + W[i];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = tmp;
    }
    h0+=a; h1+=b; h2+=c; h3+=d; h4+=e;

    uint32_t H[5] = { h0, h1, h2, h3, h4 };
    for (int i = 0; i < 5; i++) {                 /* xuất big-endian */
        out[4*i+0] = (unsigned char)(H[i] >> 24);
        out[4*i+1] = (unsigned char)(H[i] >> 16);
        out[4*i+2] = (unsigned char)(H[i] >> 8);
        out[4*i+3] = (unsigned char)(H[i]);
    }
}

/* ------------------- PHẦN 2: vòng brute (GIỐNG HỆT mọi file) ---------------- */
int main(void) {
    const char *charset = CHARSET;
    int n = (int)strlen(charset);

    unsigned char target[DIGEST_LEN];
    for (int i = 0; i < DIGEST_LEN; i++) {
        unsigned int v; sscanf(WANTED_HASH + 2*i, "%2x", &v); target[i] = (unsigned char)v;
    }

    int idx[LEN];
    for (int j = 0; j < LEN; j++) idx[j] = 0;

    char candidate[LEN + 1]; candidate[LEN] = '\0';
    unsigned char out[DIGEST_LEN];

    for (;;) {
        for (int j = 0; j < LEN; j++) candidate[j] = charset[idx[j]];
        hash((unsigned char *)candidate, LEN, out);
        if (memcmp(out, target, DIGEST_LEN) == 0) { printf("FOUND: %s\n", candidate); return 0; }
        int p = LEN - 1;
        while (p >= 0) { if (++idx[p] < n) break; idx[p] = 0; p--; }
        if (p < 0) break;
    }
    printf("Khong tim thay (LEN=%d, charset %d ky tu).\n", LEN, n);
    return 1;
}
