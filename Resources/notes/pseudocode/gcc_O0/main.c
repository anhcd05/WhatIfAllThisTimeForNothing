int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  __int64 v15[33]; // [rsp+10h] [rbp-BF0h] BYREF
  _DWORD v16[2]; // [rsp+11Ch] [rbp-AE4h] BYREF
  _DWORD v17[3]; // [rsp+124h] [rbp-ADCh] BYREF
  __int64 v18; // [rsp+130h] [rbp-AD0h] BYREF
  __int64 v19; // [rsp+138h] [rbp-AC8h] BYREF
  __int64 v20; // [rsp+140h] [rbp-AC0h] BYREF
  __int64 v21; // [rsp+148h] [rbp-AB8h] BYREF
  _BYTE v22[64]; // [rsp+150h] [rbp-AB0h] BYREF
  char v23[1024]; // [rsp+190h] [rbp-A70h] BYREF
  _BYTE s1[320]; // [rsp+590h] [rbp-670h] BYREF
  _BYTE v25[320]; // [rsp+6D0h] [rbp-530h] BYREF
  _BYTE src[320]; // [rsp+810h] [rbp-3F0h] BYREF
  char v27[320]; // [rsp+950h] [rbp-2B0h] BYREF
  _BYTE dest[260]; // [rsp+A90h] [rbp-170h] BYREF
  unsigned int v29; // [rsp+B94h] [rbp-6Ch]
  size_t v30; // [rsp+B98h] [rbp-68h]
  __int64 v31; // [rsp+BA0h] [rbp-60h]
  int kk; // [rsp+BACh] [rbp-54h]
  size_t jj; // [rsp+BB0h] [rbp-50h]
  size_t ii; // [rsp+BB8h] [rbp-48h]
  size_t m; // [rsp+BC0h] [rbp-40h]
  size_t k; // [rsp+BC8h] [rbp-38h]
  size_t j; // [rsp+BD0h] [rbp-30h]
  size_t i; // [rsp+BD8h] [rbp-28h]
  size_t n; // [rsp+BE0h] [rbp-20h]
  char *s; // [rsp+BE8h] [rbp-18h]

  if ( argc <= 1 )
    s = "Hello, CyberSeaGame!";
  else
    s = (char *)argv[1];
  n = strlen(s);
  if ( n > 0xC8 )
    n = 200;
  memcpy(dest, src: s, n);
  printf(format: "input: %.*s\n", n, s);
  b64_encode(a1: (__int64)dest, a2: n, a3: (__int64)v23);
  printf(format: "base64: %s\n", v23);
  v31 = b64_decode(a1: v23, a2: (__int64)v27);
  printf(format: "base64_dec: %.*s\n", v31, v27);
  b32_encode(a1: (__int64)dest, a2: n, a3: (__int64)v23);
  printf(format: "base32: %s\n", v23);
  b58_encode(a1: (__int64)dest, a2: n, a3: (__int64)v23);
  printf(format: "base58: %s\n", v23);
  a85_encode(a1: (__int64)dest, a2: n, a3: (__int64)v23);
  printf(format: "ascii85: %s\n", v23);
  hex_encode(a1: (__int64)dest, a2: n, a3: (__int64)v23);
  printf(format: "hex: %s\n", v23);
  memcpy(dest: v27, src: dest, n);
  rot13(a1: v27, a2: n);
  ph(a1: "rot13", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  xor_single(a1: v27, a2: n, a3: 90);
  ph(a1: "xor_single_5a", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  xor_repeat(a1: v27, a2: n, a3: "KEY", a4: 3);
  ph(a1: "xor_repeat_KEY", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  op_add(a1: v27, a2: n, a3: 7);
  ph(a1: "add_7", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  op_sub(a1: v27, a2: n, a3: 7);
  ph(a1: "sub_7", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  op_not(a1: v27, a2: n);
  ph(a1: "not", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  op_rol8(a1: v27, a2: n, a3: 3);
  ph(a1: "rol8_3", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  op_ror8(a1: v27, a2: n, a3: 3);
  ph(a1: "ror8_3", a2: v27, a3: n);
  v3 = op_ror32(a1: 305419896, a2: 8);
  v4 = op_rol32(a1: 305419896, a2: 8);
  printf(format: "rol32: %08x ror32: %08x\n", v4, v3);
  memcpy(dest: v27, src: dest, n);
  op_reverse(a1: v27, a2: n);
  ph(a1: "reverse", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  mix_chain(a1: v27, a2: n);
  ph(a1: "mix_chain", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  rc4_crypt(a1: "CyberSea", a2: 8, a3: v27, a4: n);
  ph(a1: "rc4_CyberSea", a2: v27, a3: n);
  v30 = pad_to(a1: dest, a2: n, a3: 8, a4: src);
  memcpy(dest: v25, src, n: v30);
  for ( i = 0; i < v30; i += 8LL )
  {
    v21 = *(_QWORD *)&v25[i];
    tea_encrypt(a1: &v21, a2: &tk_0);
    *(_QWORD *)&v25[i] = v21;
  }
  ph(a1: "tea_ecb", a2: v25, a3: v30);
  memcpy(dest: s1, src: v25, n: v30);
  for ( j = 0; j < v30; j += 8LL )
  {
    v20 = *(_QWORD *)&s1[j];
    tea_decrypt(a1: &v20, a2: &tk_0);
    *(_QWORD *)&s1[j] = v20;
  }
  v5 = memcmp(s1, s2: src, n: v30);
  printf(format: "tea_dec_ok: %d\n", v5 == 0);
  memcpy(dest: v25, src, n: v30);
  for ( k = 0; k < v30; k += 8LL )
  {
    v19 = *(_QWORD *)&v25[k];
    xtea_encrypt(a1: &v19, a2: &tk_0);
    *(_QWORD *)&v25[k] = v19;
  }
  ph(a1: "xtea_ecb", a2: v25, a3: v30);
  memcpy(dest: s1, src: v25, n: v30);
  for ( m = 0; m < v30; m += 8LL )
  {
    v18 = *(_QWORD *)&s1[m];
    xtea_decrypt(a1: &v18, a2: &tk_0);
    *(_QWORD *)&s1[m] = v18;
  }
  v6 = memcmp(s1, s2: src, n: v30);
  printf(format: "xtea_dec_ok: %d\n", v6 == 0);
  v29 = v30 >> 2;
  memcpy(dest: v15, src, n: v30);
  xxtea_encrypt(a1: v15, a2: v29, a3: &tk_0);
  ph(a1: "xxtea", a2: v15, a3: v30);
  xxtea_decrypt(a1: v15, a2: v29, a3: &tk_0);
  v7 = memcmp(s1: v15, s2: src, n: v30);
  printf(format: "xxtea_dec_ok: %d\n", v7 == 0);
  aes128_key_expand(a1: (__int64 *)"0123456789abcdef", a2: v15);
  v30 = pad_to(a1: dest, a2: n, a3: 16, a4: src);
  memcpy(dest: v25, src, n: v30);
  for ( ii = 0; ii < v30; ii += 16LL )
    aes128_encrypt_block(a1: (__int64)v15, a2: (__int64)&src[ii], a3: &v25[ii]);
  ph(a1: "aes128_ecb", a2: v25, a3: v30);
  for ( jj = 0; jj < v30; jj += 16LL )
    aes128_decrypt_block(a1: (__int64)v15, a2: (__int64)&v25[jj], a3: &s1[jj]);
  v8 = memcmp(s1, s2: src, n: v30);
  printf(format: "aes_dec_ok: %d\n", v8 == 0);
  v17[0] = 50462976;
  v17[1] = 117835012;
  v17[2] = 185207048;
  v16[0] = 50462976;
  v16[1] = 117835012;
  for ( kk = 0; kk <= 7; ++kk )
    *((_DWORD *)v15 + kk) = ((4 * kk + 3) << 24) | ((4 * kk + 2) << 16) | ((4 * kk + 1) << 8) | (4 * kk);
  memcpy(dest: v27, src: dest, n);
  chacha20_xor(a1: (__int64)v15, a2: (__int64)v17, a3: (__int64)v27, a4: n);
  ph(a1: "chacha20", a2: v27, a3: n);
  memcpy(dest: v27, src: dest, n);
  salsa20_xor(a1: v15, a2: v16, a3: v27, a4: n);
  ph(a1: "salsa20", a2: v27, a3: n);
  md5_hash(a1: dest, a2: n, a3: v22);
  ph(a1: "md5", a2: v22, a3: 16);
  sha1_hash(a1: dest, a2: n, a3: v22);
  ph(a1: "sha1", a2: v22, a3: 20);
  sha256_hash(a1: dest, a2: n, a3: v22);
  ph(a1: "sha256", a2: v22, a3: 32);
  sha512_hash(a1: dest, a2: n, a3: v22);
  ph(a1: "sha512", a2: v22, a3: 64);
  v9 = crc32_table(a1: (__int64)dest, a2: n);
  printf(format: "crc32_table: %08x\n", v9);
  v10 = crc32_bitwise(a1: (__int64)dest, a2: n);
  printf(format: "crc32_bitwise: %08x\n", v10);
  v11 = adler32_hash(a1: (__int64)dest, a2: n);
  printf(format: "adler32: %08x\n", v11);
  v12 = fnv1a_hash(a1: (__int64)dest, a2: n);
  printf(format: "fnv1a: %08x\n", v12);
  v13 = djb2_hash(a1: (__int64)dest, a2: n);
  printf(format: "djb2: %08x\n", v13);
  return 0;
}
