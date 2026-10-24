/* fast_md4.c — MD4 brute TỐI ƯU (OpenMP + single-block + early-reject).
 * gcc -O3 -march=native -fopenmp fast_md4.c -o fast_md4   (compile trên máy thi) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "e1d87a674c4efe3b2926dea36f02b840"   /* md4("Dec0d3") */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 16
#define STW  4
#define CMPW 4
#if LEN > 55
#error "1-block: LEN phai <= 55."
#endif
#define NW ((LEN + 4) / 4)
#define ROTL32(x,c) (((x)<<(c))|((x)>>(32-(c))))

static inline void compress(const uint32_t M[16], uint32_t st[STW]) {
    uint32_t a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
    uint32_t A=a,B=b,C=c,D=d;
    #define F(x,y,z) (((x)&(y))|(~(x)&(z)))
    #define G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
    #define H(x,y,z) ((x)^(y)^(z))
    #define FF(a,b,c,d,x,s) (a)=ROTL32((a)+F(b,c,d)+(x), s)
    #define GG(a,b,c,d,x,s) (a)=ROTL32((a)+G(b,c,d)+(x)+0x5a827999u, s)
    #define HH(a,b,c,d,x,s) (a)=ROTL32((a)+H(b,c,d)+(x)+0x6ed9eba1u, s)
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
    st[0]=a+A; st[1]=b+B; st[2]=c+C; st[3]=d+D;
}

static volatile int g_found = 0;
static char g_res[LEN+1];

int main(void){
    const char *cs = CHARSET; int n=(int)strlen(cs);
    unsigned char tb[DIGEST_LEN];
    for (int i=0;i<DIGEST_LEN;i++){ unsigned v; sscanf(WANTED_HASH+2*i,"%2x",&v); tb[i]=(unsigned char)v; }
    uint32_t T[CMPW];
    for (int i=0;i<CMPW;i++) T[i]=tb[4*i]|tb[4*i+1]<<8|tb[4*i+2]<<16|(uint32_t)tb[4*i+3]<<24;  /* little-endian */

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char blk[64]; memset(blk,0,64); blk[LEN]=0x80;
        uint64_t bits=(uint64_t)LEN*8;
        for (int i=0;i<8;i++) blk[56+i]=(unsigned char)(bits>>(8*i));
        uint32_t M[16];
        for (int i=0;i<16;i++) M[i]=blk[4*i]|blk[4*i+1]<<8|blk[4*i+2]<<16|(uint32_t)blk[4*i+3]<<24;
        int idx[LEN]; idx[0]=i0; for (int j=1;j<LEN;j++) idx[j]=0;
        for (;;){
            if (g_found) break;
            for (int j=0;j<LEN;j++) blk[j]=(unsigned char)cs[idx[j]];
            for (int w=0;w<NW;w++) M[w]=blk[4*w]|blk[4*w+1]<<8|blk[4*w+2]<<16|(uint32_t)blk[4*w+3]<<24;
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
