/* fast_crc32.c — brute CRC32 (IEEE 802.3, giống zlib / zip / PNG). OpenMP đa luồng.
 * gcc -O3 -march=native -fopenmp fast_crc32.c -o fast_crc32   (compile trên máy thi)
 *
 * ⚠️ CRC32 KHÔNG phải hash mật mã (tuyến tính, dễ giả mạo) — brute chỉ tiện cho chuỗi ngắn,
 *    và có thể trả về MỘT chuỗi cùng CRC chứ không chắc là chuỗi gốc (32-bit dễ đụng độ). */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

/* ----------------------------- CẤU HÌNH ------------------------------------- */
#define WANTED_HASH "c760632c"   /* crc32("Dec0d3") — 8 ký tự hex */
#define CHARSET     "ABCDEFabcdef0123456789"
#define LEN         6
/* --------------------------------------------------------------------------- */

static uint32_t TBL[256];
static void init_tbl(void){
    for (uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for (int k=0;k<8;k++) c = (c&1) ? (0xEDB88320u^(c>>1)) : (c>>1);
        TBL[i]=c;
    }
}
static inline uint32_t crc32_buf(const unsigned char *b, int n){
    uint32_t c=0xFFFFFFFFu;
    for (int i=0;i<n;i++) c = TBL[(c^b[i])&0xFF] ^ (c>>8);
    return c ^ 0xFFFFFFFFu;
}

static volatile int g_found=0;
static char g_res[LEN+1];

int main(void){
    const char *cs=CHARSET; int n=(int)strlen(cs);
    init_tbl();
    uint32_t T=(uint32_t)strtoul(WANTED_HASH, NULL, 16);

    double t0=0;
#ifdef _OPENMP
    t0=omp_get_wtime();
#endif
    #pragma omp parallel for schedule(dynamic)
    for (int i0=0;i0<n;i0++){
        if (g_found) continue;
        unsigned char buf[LEN];
        int idx[LEN]; idx[0]=i0; for (int j=1;j<LEN;j++) idx[j]=0;
        for (;;){
            if (g_found) break;
            for (int j=0;j<LEN;j++) buf[j]=(unsigned char)cs[idx[j]];
            if (crc32_buf(buf,LEN)==T){
                #pragma omp critical
                { for (int j=0;j<LEN;j++) g_res[j]=cs[idx[j]]; g_res[LEN]=0; g_found=1; }
                break;
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
