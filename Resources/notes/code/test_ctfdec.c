/* test_ctfdec.c - kiem chung ctfdec.h bang output cua binary that (input "Hello, CyberSeaGame!").
 * gcc -O2 -Wall -Wextra -o test_ctfdec test_ctfdec.c && ./test_ctfdec */
#include <stdio.h>
#include <stdlib.h>
#include "ctfdec.h"

static const char PT[] = "Hello, CyberSeaGame!";
static int fails, total;

static size_t unhex(const char *h, uint8_t *o)
{
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (uint8_t)v; }
    return n;
}

static void check(const char *name, const uint8_t *got, size_t n)
{
    int ok = n >= strlen(PT) && memcmp(got, PT, strlen(PT)) == 0;
    total++; fails += !ok;
    printf("%-18s %s\n", name, ok ? "PASS" : "FAIL");
}

int main(void)
{
    static union { uint8_t b8[256]; uint32_t w32[64]; } U;
    uint8_t *b = U.b8;
    size_t n;
    const uint32_t tk[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    static const char STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    n = ctf_b64_decode("SGVsbG8sIEN5YmVyU2VhR2FtZSE=", b, STD); check("base64", b, n);

    n = unhex("123f363635767a1923383f28093f3b1d3b373f7b", b); ctf_xor_repeat(b, n, (const uint8_t *)"\x5a", 1); check("xor 1 byte", b, n);
    n = unhex("032035272a756b062029202b1820380c24342e64", b); ctf_xor_repeat(b, n, (const uint8_t *)"KEY", 3); check("xor KEY", b, n);
    n = unhex("4f6c73737633274a80696c795a6c684e68746c28", b); ctf_undo_add(b, n, 7); check("add 7", b, n);
    n = unhex("415e65656825193c725b5e6b4c5e5a405a665e1a", b); ctf_undo_sub(b, n, 7); check("sub 7", b, n);
    n = unhex("b79a939390d3dfbc869d9a8dac9a9eb89e929ade", b); ctf_undo_not(b, n); check("not", b, n);
    n = unhex("422b63637b61011acb132b939a2b0b3a0b6b2b09", b); ctf_undo_rol8(b, n, 3); check("rol8 3", b, n);
    n = unhex("09ac8d8ded8504682f4cac4e6aac2ce82cadac24", b); ctf_undo_ror8(b, n, 3); check("ror8 3", b, n);
    n = unhex("e1e571ed71dfcaee051e05ce72510a8ee5a6fd88", b); ctf_mix_chain_decrypt(b, n); check("mix_chain", b, n);

    n = unhex("65c669cb4b6aeb217e5bef8147c271c5924aa6c8", b); ctf_rc4((const uint8_t *)"CyberSea", 8, b, n); check("rc4", b, n);

    n = unhex("d71369a988fdf9e79d5bf50b3bc388a5a28f36d3ef97db0b", b);
    for (size_t i = 0; i < n; i += 8) ctf_tea_decrypt(U.w32 + i / 4, tk);
    check("tea", b, n);
    n = unhex("a8dd00a65a66711ad2f877a1ed87f5d250b72a59dea29cab", b);
    for (size_t i = 0; i < n; i += 8) ctf_xtea_decrypt(U.w32 + i / 4, tk);
    check("xtea", b, n);
    n = unhex("5f2f35b9148c4907f9b43d1ea94d63827eaeee25722450f5", b);
    ctf_xxtea_decrypt(U.w32, (int)(n / 4), tk); check("xxtea", b, n);

    {
        ctf_aes_t c; uint8_t out[64];
        n = unhex("ba3eee3b3b71c17f89607a1ed8fdfb1e35a58dfed2fbe6c639bb69f5f7713860", b);
        ctf_aes_init(&c, (const uint8_t *)"0123456789abcdef");
        for (size_t i = 0; i < n; i += 16) ctf_aes_decrypt_block(&c, b + i, out + i);
        check("aes128", out, n);
    }
    {
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)i;
        n = unhex("585f9d7daea774de4046eac22e05a3ddf4bcbea9", b); ctf_chacha20_xor(key, nonce, b, n); check("chacha20", b, n);
        n = unhex("66c86333777b098daf10d6db7b8135b04eb62189", b); ctf_salsa20_xor(key, nonce, b, n); check("salsa20", b, n);
    }

    total++; if (ctf_crc32((const uint8_t *)PT, strlen(PT)) == 0xbc6db443u) printf("%-18s PASS\n", "crc32"); else { fails++; printf("%-18s FAIL\n", "crc32"); }
    {
        const uint8_t *p = (const uint8_t *)PT; size_t L = strlen(PT);
        uint32_t f = 2166136261u, f1 = 2166136261u, d = 5381, d1 = 5381;
        for (size_t i = 0; i < L; i++) { f = (f ^ p[i]) * 16777619u; d = d * 33 + p[i]; if (i + 1 < L) { f1 = f; d1 = d; } }
        total += 2;
        if (ctf_fnv1a_unstep(f, p[L - 1]) == f1) printf("%-18s PASS\n", "fnv1a unstep"); else { fails++; printf("%-18s FAIL\n", "fnv1a unstep"); }
        if (ctf_djb2_unstep(d, p[L - 1]) == d1) printf("%-18s PASS\n", "djb2 unstep"); else { fails++; printf("%-18s FAIL\n", "djb2 unstep"); }
    }

    printf("\n%d/%d PASS\n", total - fails, total);
    return fails != 0;
}

