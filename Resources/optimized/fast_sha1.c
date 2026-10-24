/* fast_sha1.c — SHA-1 brute TỐI ƯU (OpenMP + single-block + early-reject).
 * gcc -O3 -march=native -fopenmp fast_sha1.c -o fast_sha1   (compile trên máy thi) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "24d999353fdc5f4be32871022973a6253bc21d1b"   /* sha1("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 20
#define STW  5
#define CMPW 5
#if LEN > 55
#error "1-block: LEN phai <= 55."
#endif
#define NW ((LEN + 4) / 4)
#define ROTL32(x,c) (((x)<<(c))|((x)>>(32-(c))))

static inline void compress(const uint32_t M[16], uint32_t st[STW]) {
    uint32_t W[80];
    for (int i=0;i<16;i++) W[i]=M[i];
    for (int i=16;i<80;i++) W[i]=ROTL32(W[i-3]^W[i-8]^W[i-14]^W[i-16],1);
    uint32_t a=0x67452301,b=0xEFCDAB89,c=0x98BADCFE,d=0x10325476,e=0xC3D2E1F0;
    for (int i=0;i<80;i++){
        uint32_t f,k;
        if      (i<20){ f=(b&c)|(~b&d);          k=0x5A827999; }
        else if (i<40){ f=b^c^d;                 k=0x6ED9EBA1; }
        else if (i<60){ f=(b&c)|(b&d)|(c&d);     k=0x8F1BBCDC; }
        else          { f=b^c^d;                 k=0xCA62C1D6; }
        uint32_t t=ROTL32(a,5)+f+e+k+W[i];
        e=d; d=c; c=ROTL32(b,30); b=a; a=t;
    }
    st[0] = 0x67452301 + a; st[1] = 0xEFCDAB89 + b; st[2] = 0x98BADCFE + c;
    st[3] = 0x10325476 + d; st[4] = 0xC3D2E1F0 + e;
}

static volatile int g_found = 0;
static char g_res[LEN+1];

int main(void){
    const char *cs = CHARSET; int n=(int)strlen(cs);
    unsigned char tb[DIGEST_LEN];
    for (int i=0;i<DIGEST_LEN;i++){ unsigned v; sscanf(WANTED_HASH+2*i,"%2x",&v); tb[i]=(unsigned char)v; }
    uint32_t T[CMPW];
    for (int i=0;i<CMPW;i++)      /* SHA: digest big-endian */
        T[i]=(uint32_t)tb[4*i]<<24|tb[4*i+1]<<16|tb[4*i+2]<<8|tb[4*i+3];

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char blk[64]; memset(blk,0,64); blk[LEN]=0x80;
        uint64_t bits=(uint64_t)LEN*8;
        for (int i=0;i<8;i++) blk[63-i]=(unsigned char)(bits>>(8*i));  /* SHA: length big-endian */
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
