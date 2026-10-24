/* =============================================================================
 *  brute_md4.c  —  Brute-force tìm chuỗi có MD4 trùng hash cho trước.
 *  Template giống cả bộ (md4/md5/sha1/sha224/sha256/sha384/sha512):
 *  ĐI THI CHỈ SỬA 3 DÒNG trong phần CẤU HÌNH. Không phụ thuộc thư viện ngoài.
 *
 *  Biên dịch:  gcc -O2 brute_md4.c -o brute_md4
 *  Chạy:       ./brute_md4
 * ============================================================================= */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "e1d87a674c4efe3b2926dea36f02b840"   /* vd: md4("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 16                 /* MD4 = 16 byte (hex dài 32)             */
#if LEN > 55
#error "Ban 1-block: LEN phai <= 55."
#endif

#define ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

/* ---------- PHẦN 1: MD4 (coi như hộp đen, gọi hash(msg,len,out)) ----------- */
void hash(const unsigned char *msg, size_t len, unsigned char *out) {
    /* Padding: message + 0x80 + 0x00... + độ dài-bit (8 byte little-endian). */
    unsigned char block[64];
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (unsigned char)(bits >> (8 * i));

    /* 64 byte -> 16 word little-endian. */
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = block[4*i] | block[4*i+1] << 8 | block[4*i+2] << 16 | (uint32_t)block[4*i+3] << 24;

    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint32_t A = a, B = b, C = c, D = d;

    /* 3 vòng đặc trưng của MD4. */
    #define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
    #define G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
    #define H(x,y,z) ((x) ^ (y) ^ (z))
    #define FF(a,b,c,d,x,s) (a) = ROTL32((a) + F(b,c,d) + (x), s)
    #define GG(a,b,c,d,x,s) (a) = ROTL32((a) + G(b,c,d) + (x) + 0x5a827999u, s)
    #define HH(a,b,c,d,x,s) (a) = ROTL32((a) + H(b,c,d) + (x) + 0x6ed9eba1u, s)

    FF(A,B,C,D,M[0],3);  FF(D,A,B,C,M[1],7);  FF(C,D,A,B,M[2],11);  FF(B,C,D,A,M[3],19);
    FF(A,B,C,D,M[4],3);  FF(D,A,B,C,M[5],7);  FF(C,D,A,B,M[6],11);  FF(B,C,D,A,M[7],19);
    FF(A,B,C,D,M[8],3);  FF(D,A,B,C,M[9],7);  FF(C,D,A,B,M[10],11); FF(B,C,D,A,M[11],19);
    FF(A,B,C,D,M[12],3); FF(D,A,B,C,M[13],7); FF(C,D,A,B,M[14],11); FF(B,C,D,A,M[15],19);

    GG(A,B,C,D,M[0],3);  GG(D,A,B,C,M[4],5);  GG(C,D,A,B,M[8],9);   GG(B,C,D,A,M[12],13);
    GG(A,B,C,D,M[1],3);  GG(D,A,B,C,M[5],5);  GG(C,D,A,B,M[9],9);   GG(B,C,D,A,M[13],13);
    GG(A,B,C,D,M[2],3);  GG(D,A,B,C,M[6],5);  GG(C,D,A,B,M[10],9);  GG(B,C,D,A,M[14],13);
    GG(A,B,C,D,M[3],3);  GG(D,A,B,C,M[7],5);  GG(C,D,A,B,M[11],9);  GG(B,C,D,A,M[15],13);

    HH(A,B,C,D,M[0],3);  HH(D,A,B,C,M[8],9);  HH(C,D,A,B,M[4],11);  HH(B,C,D,A,M[12],15);
    HH(A,B,C,D,M[2],3);  HH(D,A,B,C,M[10],9); HH(C,D,A,B,M[6],11);  HH(B,C,D,A,M[14],15);
    HH(A,B,C,D,M[1],3);  HH(D,A,B,C,M[9],9);  HH(C,D,A,B,M[5],11);  HH(B,C,D,A,M[13],15);
    HH(A,B,C,D,M[3],3);  HH(D,A,B,C,M[11],9); HH(C,D,A,B,M[7],11);  HH(B,C,D,A,M[15],15);

    #undef F
    #undef G
    #undef H
    #undef FF
    #undef GG
    #undef HH

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

    unsigned char target[DIGEST_LEN];                 /* hash hex -> byte */
    for (int i = 0; i < DIGEST_LEN; i++) {
        unsigned int v; sscanf(WANTED_HASH + 2*i, "%2x", &v); target[i] = (unsigned char)v;
    }

    int idx[LEN];                                     /* "đồng hồ số" */
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
