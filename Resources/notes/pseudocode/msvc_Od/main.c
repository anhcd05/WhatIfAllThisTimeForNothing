int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  unsigned __int64 n; // [rsp+20h] [rbp-CD8h]
  size_t m; // [rsp+28h] [rbp-CD0h]
  size_t ma; // [rsp+28h] [rbp-CD0h]
  int mm; // [rsp+30h] [rbp-CC8h]
  BOOL v14; // [rsp+34h] [rbp-CC4h]
  BOOL v15; // [rsp+38h] [rbp-CC0h]
  int xn; // [rsp+3Ch] [rbp-CBCh]
  BOOL v17; // [rsp+40h] [rbp-CB8h]
  BOOL v18; // [rsp+44h] [rbp-CB4h]
  unsigned __int64 i; // [rsp+48h] [rbp-CB0h]
  size_t j; // [rsp+50h] [rbp-CA8h]
  size_t k; // [rsp+58h] [rbp-CA0h]
  size_t ii; // [rsp+60h] [rbp-C98h]
  size_t jj; // [rsp+68h] [rbp-C90h]
  size_t kk; // [rsp+70h] [rbp-C88h]
  unsigned int v25; // [rsp+78h] [rbp-C80h]
  const char *v26; // [rsp+88h] [rbp-C70h]
  unsigned int v[2]; // [rsp+90h] [rbp-C68h] BYREF
  unsigned int Src; // [rsp+98h] [rbp-C60h] BYREF
  unsigned int v29; // [rsp+A0h] [rbp-C58h] BYREF
  unsigned int v30; // [rsp+A8h] [rbp-C50h] BYREF
  unsigned int snonce[2]; // [rsp+B0h] [rbp-C48h] BYREF
  unsigned __int64 v32; // [rsp+B8h] [rbp-C40h]
  unsigned int cnonce[4]; // [rsp+C0h] [rbp-C38h] BYREF
  unsigned int ckey[8]; // [rsp+D0h] [rbp-C28h] BYREF
  unsigned int xw[64]; // [rsp+F0h] [rbp-C08h] BYREF
  unsigned __int8 w[320]; // [rsp+1F0h] [rbp-B08h] BYREF
  unsigned __int8 d64[64]; // [rsp+330h] [rbp-9C8h] BYREF
  unsigned __int8 in[256]; // [rsp+370h] [rbp-988h] BYREF
  unsigned __int8 ct[320]; // [rsp+470h] [rbp-888h] BYREF
  unsigned __int8 pt[320]; // [rsp+5B0h] [rbp-748h] BYREF
  unsigned __int8 dec[320]; // [rsp+6F0h] [rbp-608h] BYREF
  unsigned __int8 rk[176]; // [rsp+830h] [rbp-4C8h] BYREF
  char s[1024]; // [rsp+8E0h] [rbp-418h] BYREF

  if ( argc <= 1 )
    v26 = aHelloCyberseag;
  else
    v26 = argv[1];
  n = strlen(Str: v26);
  if ( n > 0xC8 )
    n = 200;
  memmove(a1: in, Src: v26, Size: n);
  printf(_Format: "input: %.*s\n", n, v26);
  b64_encode(in, n, out: s);
  printf(_Format: "base64: %s\n", s);
  v32 = b64_decode(in: s, out: w);
  printf(_Format: "base64_dec: %.*s\n", v32, (const char *)w);
  b32_encode(in, n, out: s);
  printf(_Format: "base32: %s\n", s);
  b58_encode(in, n, out: s);
  printf(_Format: "base58: %s\n", s);
  a85_encode(in, n, out: s);
  printf(_Format: "ascii85: %s\n", s);
  hex_encode(in, n, out: s);
  printf(_Format: "hex: %s\n", s);
  memmove(a1: w, Src: in, Size: n);
  rot13(s: (char *)w, n);
  ph(tag: tag, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  xor_single(b: w, n, k: 0x5Au);
  ph(tag: aXorSingle5a, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  xor_repeat(b: w, n, key: key, kl: 3u);
  ph(tag: aXorRepeatKey, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  op_add(b: w, n, k: 7u);
  ph(tag: aAdd7, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  op_sub(b: w, n, k: 7u);
  ph(tag: aSub7, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  op_not(b: w, n);
  ph(tag: aNot, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  op_rol8(b: w, n, k: 3);
  ph(tag: aRol83, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  op_ror8(b: w, n, k: 3);
  ph(tag: aRor83, p: w, n);
  v25 = op_ror32(x: 0x12345678u, k: 8);
  v3 = op_rol32(x: 0x12345678u, k: 8);
  printf(_Format: "rol32: %08x ror32: %08x\n", v3, v25);
  memmove(a1: w, Src: in, Size: n);
  op_reverse(b: w, n);
  ph(tag: aReverse, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  mix_chain(b: w, n);
  ph(tag: aMixChain, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  rc4_crypt(key: aCybersea, kl: 8u, buf: w, n);
  ph(tag: aRc4Cybersea, p: w, n);
  m = pad_to(in, n, bs: 8u, out: pt);
  memmove(a1: ct, Src: pt, Size: m);
  for ( i = 0; i < m; i += 8LL )
  {
    memmove(a1: v, Src: &ct[i], Size: 8u);
    tea_encrypt(v, k: tk);
    memmove(a1: &ct[i], Src: v, Size: 8u);
  }
  ph(tag: aTeaEcb, p: ct, n: m);
  memmove(a1: dec, Src: ct, Size: m);
  for ( j = 0; j < m; j += 8LL )
  {
    memmove(a1: &Src, Src: &dec[j], Size: 8u);
    tea_decrypt(v: &Src, k: tk);
    memmove(a1: &dec[j], &Src, Size: 8u);
  }
  v14 = memcmp(Buf1: dec, Buf2: pt, Size: m) == 0;
  printf(_Format: "tea_dec_ok: %d\n", v14);
  memmove(a1: ct, Src: pt, Size: m);
  for ( k = 0; k < m; k += 8LL )
  {
    memmove(a1: &v29, Src: &ct[k], Size: 8u);
    xtea_encrypt(v: &v29, k: tk);
    memmove(a1: &ct[k], Src: &v29, Size: 8u);
  }
  ph(tag: aXteaEcb, p: ct, n: m);
  memmove(a1: dec, Src: ct, Size: m);
  for ( ii = 0; ii < m; ii += 8LL )
  {
    memmove(a1: &v30, Src: &dec[ii], Size: 8u);
    xtea_decrypt(v: &v30, k: tk);
    memmove(a1: &dec[ii], Src: &v30, Size: 8u);
  }
  v15 = memcmp(Buf1: dec, Buf2: pt, Size: m) == 0;
  printf(_Format: "xtea_dec_ok: %d\n", v15);
  xn = m / 4;
  memmove(a1: xw, Src: pt, Size: m);
  xxtea_encrypt(v: xw, n: xn, key: tk);
  ph(tag: aXxtea, p: (const unsigned __int8 *)xw, n: m);
  xxtea_decrypt(v: xw, n: xn, key: tk);
  v17 = memcmp(Buf1: xw, Buf2: pt, Size: m) == 0;
  printf(_Format: "xxtea_dec_ok: %d\n", v17);
  aes128_key_expand(key: a0123456789abcd, rk);
  ma = pad_to(in, n, bs: 0x10u, out: pt);
  memmove(a1: ct, Src: pt, Size: ma);
  for ( jj = 0; jj < ma; jj += 16LL )
    aes128_encrypt_block(rk, in: &pt[jj], out: &ct[jj]);
  ph(tag: aAes128Ecb, p: ct, n: ma);
  for ( kk = 0; kk < ma; kk += 16LL )
    aes128_decrypt_block(rk, in: &ct[kk], out: &dec[kk]);
  v18 = memcmp(Buf1: dec, Buf2: pt, Size: ma) == 0;
  printf(_Format: "aes_dec_ok: %d\n", v18);
  cnonce[0] = 50462976;
  cnonce[1] = 117835012;
  cnonce[2] = 185207048;
  snonce[0] = 50462976;
  snonce[1] = 117835012;
  for ( mm = 0; mm < 8; ++mm )
    ckey[mm] = ((4 * mm + 3) << 24) | ((4 * mm + 2) << 16) | ((4 * mm + 1) << 8) | (4 * mm);
  memmove(a1: w, Src: in, Size: n);
  chacha20_xor(key: ckey, nonce: cnonce, buf: w, n);
  ph(tag: aChacha20, p: w, n);
  memmove(a1: w, Src: in, Size: n);
  salsa20_xor(key: ckey, nonce: snonce, buf: w, n);
  ph(tag: aSalsa20, p: w, n);
  md5_hash(msg: in, n, out: d64);
  ph(tag: aMd5, p: d64, n: 0x10u);
  sha1_hash(msg: in, n, out: d64);
  ph(tag: aSha1, p: d64, n: 0x14u);
  sha256_hash(msg: in, n, out: d64);
  ph(tag: aSha256, p: d64, n: 0x20u);
  sha512_hash(msg: in, n, out: d64);
  ph(tag: aSha512, p: d64, n: 0x40u);
  v4 = crc32_table(p: in, n);
  printf(_Format: "crc32_table: %08x\n", v4);
  v5 = crc32_bitwise(p: in, n);
  printf(_Format: "crc32_bitwise: %08x\n", v5);
  v6 = adler32_hash(p: in, n);
  printf(_Format: "adler32: %08x\n", v6);
  v7 = fnv1a_hash(p: in, n);
  printf(_Format: "fnv1a: %08x\n", v7);
  v8 = djb2_hash(p: in, n);
  printf(_Format: "djb2: %08x\n", v8);
  return 0;
}
