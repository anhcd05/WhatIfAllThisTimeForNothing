void __fastcall aes128_decrypt_block(const unsigned __int8 *rk, const unsigned __int8 *in, unsigned __int8 *out)
{
  unsigned __int8 a0; // [rsp+20h] [rbp-88h]
  unsigned __int8 a1; // [rsp+21h] [rbp-87h]
  unsigned __int8 a2; // [rsp+22h] [rbp-86h]
  unsigned __int8 a3; // [rsp+23h] [rbp-85h]
  int k; // [rsp+24h] [rbp-84h]
  int i; // [rsp+28h] [rbp-80h]
  int rr; // [rsp+2Ch] [rbp-7Ch]
  int j; // [rsp+30h] [rbp-78h]
  int c; // [rsp+34h] [rbp-74h]
  int r; // [rsp+38h] [rbp-70h]
  unsigned __int8 v13; // [rsp+3Ch] [rbp-6Ch]
  char v14; // [rsp+40h] [rbp-68h]
  char v15; // [rsp+44h] [rbp-64h]
  unsigned __int8 v16; // [rsp+48h] [rbp-60h]
  char v17; // [rsp+4Ch] [rbp-5Ch]
  char v18; // [rsp+50h] [rbp-58h]
  unsigned __int8 v19; // [rsp+54h] [rbp-54h]
  char v20; // [rsp+58h] [rbp-50h]
  char v21; // [rsp+5Ch] [rbp-4Ch]
  unsigned __int8 v22; // [rsp+60h] [rbp-48h]
  char v23; // [rsp+64h] [rbp-44h]
  char v24; // [rsp+68h] [rbp-40h]
  unsigned __int8 t[16]; // [rsp+70h] [rbp-38h] BYREF
  unsigned __int8 s[16]; // [rsp+80h] [rbp-28h] BYREF

  for ( i = 0; i < 16; ++i )
    s[i] = rk[i + 160] ^ in[i];
  for ( r = 9; r >= 0; --r )
  {
    for ( c = 0; c < 4; ++c )
    {
      for ( rr = 0; rr < 4; ++rr )
        t[4 * c + rr] = AES_INV_SBOX[s[4 * (((unsigned __int8)c - (unsigned __int8)rr + 4) & 3) + rr]];
    }
    for ( j = 0; j < 16; ++j )
      t[j] ^= rk[16 * r + j];
    if ( r <= 0 )
    {
      memmove(a1: s, Src: t, Size: 0x10u);
    }
    else
    {
      for ( k = 0; k < 4; ++k )
      {
        a0 = t[4 * k];
        a1 = t[4 * k + 1];
        a2 = t[4 * k + 2];
        a3 = t[4 * k + 3];
        v13 = gm(a: a0, b: 0xEu);
        v14 = gm(a: a1, b: 0xBu) ^ v13;
        v15 = gm(a: a2, b: 0xDu) ^ v14;
        s[4 * k] = gm(a: a3, b: 9u) ^ v15;
        v16 = gm(a: a0, b: 9u);
        v17 = gm(a: a1, b: 0xEu) ^ v16;
        v18 = gm(a: a2, b: 0xBu) ^ v17;
        s[4 * k + 1] = gm(a: a3, b: 0xDu) ^ v18;
        v19 = gm(a: a0, b: 0xDu);
        v20 = gm(a: a1, b: 9u) ^ v19;
        v21 = gm(a: a2, b: 0xEu) ^ v20;
        s[4 * k + 2] = gm(a: a3, b: 0xBu) ^ v21;
        v22 = gm(a: a0, b: 0xBu);
        v23 = gm(a: a1, b: 0xDu) ^ v22;
        v24 = gm(a: a2, b: 9u) ^ v23;
        s[4 * k + 3] = gm(a: a3, b: 0xEu) ^ v24;
      }
    }
  }
  memmove(a1: out, Src: s, Size: 0x10u);
}
