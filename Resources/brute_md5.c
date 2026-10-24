/* =============================================================================
 *  brute_md5.c  —  Brute-force tìm chuỗi có MD5 trùng hash cho trước.
 *  ĐI THI CHỈ SỬA 3 DÒNG trong phần CẤU HÌNH. Không phụ thuộc thư viện ngoài.
 *
 *  Biên dịch:  gcc -O2 brute_md5.c -o brute_md5
 *  Chạy:       ./brute_md5
 * ============================================================================= */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "d974e538cf501afdfc3986041c5a3993"   /* vd: md5("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 16                 /* MD5 = 16 byte (hex dài 32)             */
#if LEN > 55
#error "Ban 1-block: LEN phai <= 55."
#endif

#define ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

/* ---------- PHẦN 1: MD5 (coi như hộp đen, gọi hash(msg,len,out)) ----------- */
void hash(const unsigned char *msg, size_t len, unsigned char *out) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21};

    /* Padding (1 block): message + 0x80 + 0x00... + độ dài-bit 8 byte little-endian. */
    unsigned char block[64];
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (unsigned char)(bits >> (8 * i));

    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = block[4*i] | block[4*i+1] << 8 | block[4*i+2] << 16 | (uint32_t)block[4*i+3] << 24;

    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint32_t A = a, B = b, C = c, D = d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if      (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;          g = (3*i + 5) % 16; }
        else             { F = C ^ (B | ~D);       g = (7*i)     % 16; }
        F += A + K[i] + M[g];
        A = D; D = C; C = B;
        B += ROTL32(F, S[i]);
    }
    a += A; b += B; c += C; d += D;
    uint32_t w[4] = { a, b, c, d };
    for (int i = 0; i < 4; i++) {                 /* xuất little-endian */
        out[4*i+0] = (unsigned char)(w[i]);
        out[4*i+1] = (unsigned char)(w[i] >> 8);
        out[4*i+2] = (unsigned char)(w[i] >> 16);
        out[4*i+3] = (unsigned char)(w[i] >> 24);
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
