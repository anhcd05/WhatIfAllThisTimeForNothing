/* fast_sha384.c — SHA-384 brute TỐI ƯU (OpenMP + single-block + early-reject).
 * Giống SHA-512, chỉ khác IV và so 6 word (48 byte).
 * gcc -O3 -march=native -fopenmp fast_sha384.c -o fast_sha384   (compile trên máy thi) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "ce2959aa54a78126d3d978621c92eeadbfa3d608fd00241bb5f5270e9da6a95eca81a86db84d96ed5a7f6cddc7013083" /* sha384("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 48
#define STW  8
#define CMPW 6                 /* 48/8 = 6 word */
#if LEN > 111
#error "1-block (128 byte): LEN phai <= 111."
#endif
#define NW ((LEN + 8) / 8)
#define ROTR64(x,c) (((x)>>(c))|((x)<<(64-(c))))

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

static inline void compress(const uint64_t M[16], uint64_t st[STW]) {
    uint64_t W[80];
    for (int i=0;i<16;i++) W[i]=M[i];
    for (int i=16;i<80;i++){
        uint64_t s0=ROTR64(W[i-15],1)^ROTR64(W[i-15],8)^(W[i-15]>>7);
        uint64_t s1=ROTR64(W[i-2],19)^ROTR64(W[i-2],61)^(W[i-2]>>6);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    uint64_t a=0xcbbb9d5dc1059ed8ULL,b=0x629a292a367cd507ULL,c=0x9159015a3070dd17ULL,d=0x152fecd8f70e5939ULL,
             e=0x67332667ffc00b31ULL,f=0x8eb44a8768581511ULL,g=0xdb0c2e0d64f98fa7ULL,h=0x47b5481dbefa4fa4ULL;
    for (int i=0;i<80;i++){
        uint64_t S1=ROTR64(e,14)^ROTR64(e,18)^ROTR64(e,41);
        uint64_t ch=(e&f)^(~e&g);
        uint64_t t1=h+S1+ch+K[i]+W[i];
        uint64_t S0=ROTR64(a,28)^ROTR64(a,34)^ROTR64(a,39);
        uint64_t maj=(a&b)^(a&c)^(b&c);
        uint64_t t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]=0xcbbb9d5dc1059ed8ULL+a; st[1]=0x629a292a367cd507ULL+b; st[2]=0x9159015a3070dd17ULL+c; st[3]=0x152fecd8f70e5939ULL+d;
    st[4]=0x67332667ffc00b31ULL+e; st[5]=0x8eb44a8768581511ULL+f; st[6]=0xdb0c2e0d64f98fa7ULL+g; st[7]=0x47b5481dbefa4fa4ULL+h;
}

static volatile int g_found = 0;
static char g_res[LEN+1];

int main(void){
    const char *cs = CHARSET; int n=(int)strlen(cs);
    unsigned char tb[DIGEST_LEN];
    for (int i=0;i<DIGEST_LEN;i++){ unsigned v; sscanf(WANTED_HASH+2*i,"%2x",&v); tb[i]=(unsigned char)v; }
    uint64_t T[CMPW];
    for (int i=0;i<CMPW;i++){ uint64_t w=0; for(int j=0;j<8;j++) w=(w<<8)|tb[8*i+j]; T[i]=w; }

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char blk[128]; memset(blk,0,128); blk[LEN]=0x80;
        uint64_t bits=(uint64_t)LEN*8;
        for (int i=0;i<8;i++) blk[127-i]=(unsigned char)(bits>>(8*i));
        uint64_t M[16];
        for (int i=0;i<16;i++){ uint64_t w=0; for(int j=0;j<8;j++) w=(w<<8)|blk[8*i+j]; M[i]=w; }
        int idx[LEN]; idx[0]=i0; for (int j=1;j<LEN;j++) idx[j]=0;
        for (;;){
            if (g_found) break;
            for (int j=0;j<LEN;j++) blk[j]=(unsigned char)cs[idx[j]];
            for (int wd=0;wd<NW;wd++){ uint64_t w=0; for(int j=0;j<8;j++) w=(w<<8)|blk[8*wd+j]; M[wd]=w; }
            uint64_t st[STW]; compress(M,st);
            if (st[0]==T[0]){
                int ok=1; for (int w=1;w<CMPW;w++) if (st[w]!=T[w]){ ok=0; break; }
                if (ok){
                    #pragma omp critical
                    { for (int j=0;j<LEN;j++) g_res[j]=cs[idx[j]]; g_res[LEN]=0; g_found=1; }
                    break;
                }
            }
            int p=LEN-1; for (;p>=1;p--){ if (++idx[p]<n) break; idx[p]=0; } if (p<1) break;
        }
    }
    if (g_found) printf("FOUND: %s\n", g_res);
    else printf("Khong tim thay (LEN=%d, charset %d).\n", LEN, n);
#ifdef _OPENMP
    { double s=omp_get_wtime()-t0; double tot=1; for(int j=0;j<LEN;j++) tot*=n;
      printf("Thoi gian: %.3f s  (~%.0fM to hop, %.1f M/s)\n", s, tot/1e6, s>0?tot/s/1e6:0); }
#endif
    return g_found?0:1;
}
