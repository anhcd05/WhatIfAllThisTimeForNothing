void __fastcall aes128_key_expand(const unsigned __int8 *key, unsigned __int8 *rk)
{
  unsigned __int8 rc; // [rsp+20h] [rbp-18h]
  unsigned __int8 u; // [rsp+21h] [rbp-17h]
  unsigned __int8 t[4]; // [rsp+24h] [rbp-14h] BYREF
  int i; // [rsp+28h] [rbp-10h]
  int j; // [rsp+2Ch] [rbp-Ch]

  rc = 1;
  memmove(a1: rk, Src: key, Size: 0x10u);
  for ( i = 16; i < 176; i += 4 )
  {
    memmove(a1: t, Src: &rk[i - 4], Size: 4u);
    if ( i % 16 == 0 )
    {
      u = t[0];
      t[0] = rc ^ AES_SBOX[t[1]];
      t[1] = AES_SBOX[t[2]];
      t[2] = AES_SBOX[t[3]];
      t[3] = AES_SBOX[u];
      rc = xt(x: rc);
    }
    for ( j = 0; j < 4; ++j )
      rk[j + i] = t[j] ^ rk[i - 16 + j];
  }
}
