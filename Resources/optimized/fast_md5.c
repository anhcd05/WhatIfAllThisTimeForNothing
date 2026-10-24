/* fast_md5.c — MD5 brute TỐI ƯU (OpenMP đa luồng + single-block + early-reject).
 * Biên dịch NGAY TRÊN MÁY THI (đừng mang .exe sẵn):
 *     gcc -O3 -march=native -fopenmp fast_md5.c -o fast_md5
 * Đi thi chỉ sửa 3 dòng CẤU HÌNH. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "53578cc8c5c0a6a19c571a1fa6bcab85"   /* md5("Dec0d3") */
#define CHARSET     "0123456789"
#define LEN         8
/* --------------------------------------------------------------------------- */

#define DIGEST_LEN 16
#define STW  4                 /* số state word compress trả về */
#define CMPW 4                 /* số word cần so (DIGEST_LEN/4)  */
#if LEN > 55
#error "1-block: LEN phai <= 55."
#endif
#define NW ((LEN + 4) / 4)     /* số word của block bị message động vào */
#define ROTL32(x,c) (((x)<<(c))|((x)>>(32-(c))))

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

static inline void compress(const uint32_t M[16], uint32_t st[STW]) {
    uint32_t a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
    uint32_t A=a,B=b,C=c,D=d;
    for (int i=0;i<64;i++){
        uint32_t F; int g;
        if      (i<16){ F=(B&C)|(~B&D);  g=i; }
        else if (i<32){ F=(D&B)|(~D&C);  g=(5*i+1)&15; }
        else if (i<48){ F=B^C^D;         g=(3*i+5)&15; }
        else          { F=C^(B|~D);      g=(7*i)&15; }
        F += A + K[i] + M[g];
        A=D; D=C; C=B; B += ROTL32(F,S[i]);
    }
    st[0]=a+A; st[1]=b+B; st[2]=c+C; st[3]=d+D;
}

static volatile int g_found = 0;
static char g_res[LEN+1];

int main(void){
    const char *cs = CHARSET; int n=(int)strlen(cs);

    unsigned char tb[DIGEST_LEN];
    for (int i=0;i<DIGEST_LEN;i++){ unsigned v; sscanf(WANTED_HASH+2*i,"%2x",&v); tb[i]=(unsigned char)v; }
    uint32_t T[CMPW];
    for (int i=0;i<CMPW;i++)      /* MD5: digest little-endian */
        T[i]=tb[4*i]|tb[4*i+1]<<8|tb[4*i+2]<<16|(uint32_t)tb[4*i+3]<<24;

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char blk[64]; memset(blk,0,64); blk[LEN]=0x80;
        uint64_t bits=(uint64_t)LEN*8;
        for (int i=0;i<8;i++) blk[56+i]=(unsigned char)(bits>>(8*i));  /* MD: length little-endian */
        uint32_t M[16];
        for (int i=0;i<16;i++) M[i]=blk[4*i]|blk[4*i+1]<<8|blk[4*i+2]<<16|(uint32_t)blk[4*i+3]<<24;

        int idx[LEN]; idx[0]=i0; for (int j=1;j<LEN;j++) idx[j]=0;
        for (;;){
            if (g_found) break;
            for (int j=0;j<LEN;j++) blk[j]=(unsigned char)cs[idx[j]];
            for (int w=0;w<NW;w++) M[w]=blk[4*w]|blk[4*w+1]<<8|blk[4*w+2]<<16|(uint32_t)blk[4*w+3]<<24;
            uint32_t st[STW]; compress(M,st);
            if (st[0]==T[0]){                 /* early-reject: loại ~99.99% chỉ bằng 1 phép so */
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
