/* =============================================================================
 *  brute_sha256.c  —  Brute-force tìm chuỗi có SHA-256 trùng hash cho trước.
 *  ĐI THI CHỈ SỬA 3 DÒNG trong phần CẤU HÌNH. Không phụ thuộc thư viện ngoài.
 *
 *  Biên dịch:  gcc -O2 brute_sha256.c -o brute_sha256
 *  Chạy:       ./brute_sha256
 * ============================================================================= */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "0abefe1fb88827bb302fcbc086a416cb7d8f3536ed2150bf5dbefceace8d2335" /* sha256("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 32                 /* SHA-256 = 32 byte (hex dài 64)         */
#if LEN > 55
#error "Ban 1-block: LEN phai <= 55."
#endif

#define ROTR32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))

/* ---------- PHẦN 1: SHA-256 (hộp đen, BIG-ENDIAN). ------------------------- */
void hash(const unsigned char *msg, size_t len, unsigned char *out) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

    unsigned char block[64];
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[63 - i] = (unsigned char)(bits >> (8 * i));

    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = (uint32_t)block[4*i] << 24 | block[4*i+1] << 16 | block[4*i+2] << 8 | block[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(W[i-15],7) ^ ROTR32(W[i-15],18) ^ (W[i-15] >> 3);
        uint32_t s1 = ROTR32(W[i-2],17) ^ ROTR32(W[i-2],19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    /* IV của SHA-256. (SHA-224 chỉ khác IV và cắt output — xem brute_sha224.c) */
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
             h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;

    uint32_t H[8] = { h0,h1,h2,h3,h4,h5,h6,h7 };
    for (int i = 0; i < 8; i++) {                 /* xuất big-endian, 32 byte */
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
