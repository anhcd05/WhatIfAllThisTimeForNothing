/* fast_sha256.c — SHA-256 brute TỐI ƯU (OpenMP + single-block + early-reject).
 * gcc -O3 -march=native -fopenmp fast_sha256.c -o fast_sha256   (compile trên máy thi) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "0abefe1fb88827bb302fcbc086a416cb7d8f3536ed2150bf5dbefceace8d2335" /* sha256("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 32
#define STW  8
#define CMPW 8
#if LEN > 55
#error "1-block: LEN phai <= 55."
#endif
#define NW ((LEN + 4) / 4)
#define ROTR32(x,c) (((x)>>(c))|((x)<<(32-(c))))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static inline void compress(const uint32_t M[16], uint32_t st[STW]) {
    uint32_t W[64];
    for (int i=0;i<16;i++) W[i]=M[i];
    for (int i=16;i<64;i++){
        uint32_t s0=ROTR32(W[i-15],7)^ROTR32(W[i-15],18)^(W[i-15]>>3);
        uint32_t s1=ROTR32(W[i-2],17)^ROTR32(W[i-2],19)^(W[i-2]>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,
             e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    for (int i=0;i<64;i++){
        uint32_t S1=ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+K[i]+W[i];
        uint32_t S0=ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]=0x6a09e667+a; st[1]=0xbb67ae85+b; st[2]=0x3c6ef372+c; st[3]=0xa54ff53a+d;
    st[4]=0x510e527f+e; st[5]=0x9b05688c+f; st[6]=0x1f83d9ab+g; st[7]=0x5be0cd19+h;
}

static volatile int g_found = 0;
static char g_res[LEN+1];

int main(void){
    const char *cs = CHARSET; int n=(int)strlen(cs);
    unsigned char tb[DIGEST_LEN];
    for (int i=0;i<DIGEST_LEN;i++){ unsigned v; sscanf(WANTED_HASH+2*i,"%2x",&v); tb[i]=(unsigned char)v; }
    uint32_t T[CMPW];
    for (int i=0;i<CMPW;i++) T[i]=(uint32_t)tb[4*i]<<24|tb[4*i+1]<<16|tb[4*i+2]<<8|tb[4*i+3];

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char blk[64]; memset(blk,0,64); blk[LEN]=0x80;
        uint64_t bits=(uint64_t)LEN*8;
        for (int i=0;i<8;i++) blk[63-i]=(unsigned char)(bits>>(8*i));
        uint32_t M[16];
        for (int i=0;i<16;i++) M[i]=(uint32_t)blk[4*i]<<24|blk[4*i+1]<<16|blk[4*i+2]<<8|blk[4*i+3];
        int idx[LEN]; idx[0]=i0; for (int j=1;j<LEN;j++) idx[j]=0;
        for (;;){
            if (g_found) break;
            for (int j=0;j<LEN;j++) blk[j]=(unsigned char)cs[idx[j]];
            for (int w=0;w<NW;w++) M[w]=(uint32_t)blk[4*w]<<24|blk[4*w+1]<<16|blk[4*w+2]<<8|blk[4*w+3];
            uint32_t st[STW]; compress(M,st);
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
