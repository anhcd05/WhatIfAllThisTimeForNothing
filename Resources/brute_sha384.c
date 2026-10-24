/* =============================================================================
 *  brute_sha384.c  —  Brute-force tìm chuỗi có SHA-384 trùng hash cho trước.
 *  Giống hệt SHA-512, chỉ khác IV khởi tạo và cắt output còn 48 byte.
 *  ĐI THI CHỈ SỬA 3 DÒNG trong phần CẤU HÌNH. Không phụ thuộc thư viện ngoài.
 *
 *  Biên dịch:  gcc -O2 brute_sha384.c -o brute_sha384
 * ============================================================================= */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "ce2959aa54a78126d3d978621c92eeadbfa3d608fd00241bb5f5270e9da6a95eca81a86db84d96ed5a7f6cddc7013083" /* sha384("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 48                 /* SHA-384 = 48 byte (hex dài 96)         */
#if LEN > 111
#error "Ban 1-block (128 byte): LEN phai <= 111."
#endif

#define ROTR64(x, c) (((x) >> (c)) | ((x) << (64 - (c))))

/* ---------- PHẦN 1: SHA-384 (hộp đen, BIG-ENDIAN, 64-bit). ----------------- */
void hash(const unsigned char *msg, size_t len, unsigned char *out) {
    static const uint64_t K[80] = {
        0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
        0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
        0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
        0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

    unsigned char block[128];
    memset(block, 0, 128);
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[127 - i] = (unsigned char)(bits >> (8 * i));

    uint64_t W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = 0;
        for (int j = 0; j < 8; j++) W[i] = (W[i] << 8) | block[8*i + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROTR64(W[i-15],1) ^ ROTR64(W[i-15],8) ^ (W[i-15] >> 7);
        uint64_t s1 = ROTR64(W[i-2],19) ^ ROTR64(W[i-2],61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    /* IV của SHA-384 (khác SHA-512). */
    uint64_t h0=0xcbbb9d5dc1059ed8ULL,h1=0x629a292a367cd507ULL,h2=0x9159015a3070dd17ULL,h3=0x152fecd8f70e5939ULL,
             h4=0x67332667ffc00b31ULL,h5=0x8eb44a8768581511ULL,h6=0xdb0c2e0d64f98fa7ULL,h7=0x47b5481dbefa4fa4ULL;
    uint64_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROTR64(e,14) ^ ROTR64(e,18) ^ ROTR64(e,41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K[i] + W[i];
        uint64_t S0 = ROTR64(a,28) ^ ROTR64(a,34) ^ ROTR64(a,39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;

    /* SHA-384 chỉ lấy 6 word đầu = 48 byte. */
    uint64_t H[8] = { h0,h1,h2,h3,h4,h5,h6,h7 };
    for (int i = 0; i < 6; i++)
        for (int j = 0; j < 8; j++)
            out[8*i + j] = (unsigned char)(H[i] >> (56 - 8*j));
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
