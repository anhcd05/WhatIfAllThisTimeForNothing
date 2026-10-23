void __fastcall aes128_encrypt_block(const unsigned __int8 *rk, const unsigned __int8 *in, unsigned __int8 *out)
{
  unsigned __int8 a0; // [rsp+20h] [rbp-68h]
  unsigned __int8 a1; // [rsp+21h] [rbp-67h]
  unsigned __int8 a2; // [rsp+22h] [rbp-66h]
  unsigned __int8 a3; // [rsp+23h] [rbp-65h]
  int j; // [rsp+24h] [rbp-64h]
  int i; // [rsp+28h] [rbp-60h]
  int rr; // [rsp+2Ch] [rbp-5Ch]
  int k; // [rsp+30h] [rbp-58h]
  int c; // [rsp+34h] [rbp-54h]
  int r; // [rsp+38h] [rbp-50h]
  unsigned __int8 v13; // [rsp+3Ch] [rbp-4Ch]
  char v14; // [rsp+44h] [rbp-44h]
  char v15; // [rsp+4Ch] [rbp-3Ch]
  int v16; // [rsp+50h] [rbp-38h]
  unsigned __int8 s[16]; // [rsp+58h] [rbp-30h] BYREF
  unsigned __int8 t[16]; // [rsp+68h] [rbp-20h] BYREF

  for ( i = 0; i < 16; ++i )
    s[i] = rk[i] ^ in[i];
  for ( r = 1; r <= 10; ++r )
  {
    for ( c = 0; c < 4; ++c )
    {
      for ( rr = 0; rr < 4; ++rr )
        t[4 * c + rr] = AES_SBOX[s[4 * (((unsigned __int8)rr + (unsigned __int8)c) & 3) + rr]];
    }
    if ( r >= 10 )
    {
      memmove(a1: s, Src: t, Size: 0x10u);
    }
    else
    {
      for ( j = 0; j < 4; ++j )
      {
        a0 = t[4 * j];
        a1 = t[4 * j + 1];
        a2 = t[4 * j + 2];
        a3 = t[4 * j + 3];
        v13 = xt(x: a0);
        s[4 * j] = a3 ^ a2 ^ a1 ^ xt(x: a1) ^ v13;
        v14 = xt(x: a1) ^ a0;
        s[4 * j + 1] = a3 ^ a2 ^ xt(x: a2) ^ v14;
        v15 = xt(x: a2) ^ a1 ^ a0;
        s[4 * j + 2] = a3 ^ xt(x: a3) ^ v15;
        v16 = a2 ^ a1 ^ a0 ^ xt(x: a0);
        s[4 * j + 3] = xt(x: a3) ^ v16;
      }
    }
    for ( k = 0; k < 16; ++k )
      s[k] ^= rk[16 * r + k];
  }
  memmove(a1: out, Src: s, Size: 0x10u);
}
