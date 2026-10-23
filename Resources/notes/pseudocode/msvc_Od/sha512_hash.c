void __fastcall sha512_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  int ii; // [rsp+20h] [rbp-528h]
  int i; // [rsp+24h] [rbp-524h]
  int k; // [rsp+28h] [rbp-520h]
  int m; // [rsp+2Ch] [rbp-51Ch]
  int jj; // [rsp+30h] [rbp-518h]
  int mm; // [rsp+34h] [rbp-514h]
  int kk; // [rsp+38h] [rbp-510h]
  unsigned __int64 a; // [rsp+40h] [rbp-508h]
  unsigned __int64 e; // [rsp+48h] [rbp-500h]
  int j; // [rsp+50h] [rbp-4F8h]
  unsigned __int64 b; // [rsp+58h] [rbp-4F0h]
  unsigned __int64 c; // [rsp+60h] [rbp-4E8h]
  unsigned __int64 off; // [rsp+68h] [rbp-4E0h]
  unsigned __int64 f; // [rsp+70h] [rbp-4D8h]
  unsigned __int64 g; // [rsp+78h] [rbp-4D0h]
  unsigned __int64 v; // [rsp+80h] [rbp-4C8h]
  unsigned __int64 d; // [rsp+88h] [rbp-4C0h]
  unsigned __int64 h; // [rsp+90h] [rbp-4B8h]
  unsigned __int64 total; // [rsp+98h] [rbp-4B0h]
  unsigned __int64 t1; // [rsp+A0h] [rbp-4A8h]
  unsigned __int64 bits; // [rsp+A8h] [rbp-4A0h]
  unsigned __int64 t2; // [rsp+E0h] [rbp-468h]
  unsigned __int64 H[8]; // [rsp+F0h] [rbp-458h]
  unsigned __int64 w[80]; // [rsp+130h] [rbp-418h]
  unsigned __int8 buf[384]; // [rsp+3B0h] [rbp-198h] BYREF

  total = ((n + 16) / 0x80 + 1) << 7;
  bits = 8 * n;
  for ( i = 0; i < 8; ++i )
    H[i] = SHA512_H0[i];
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  for ( k = 0; k < 8; ++k )
    buf[total - 1 - k] = bits >> (8 * (unsigned __int8)k);
  for ( off = 0; off < total; off += 128LL )
  {
    for ( m = 0; m < 16; ++m )
    {
      v = 0;
      for ( j = 0; j < 8; ++j )
        v = buf[8 * m + j + off] | (v << 8);
      w[m] = v;
    }
    for ( ii = 16; ii < 80; ++ii )
      w[ii] = ((w[ii - 2] >> 6) ^ ((8 * w[ii - 2]) | (w[ii - 2] >> 61)) ^ ((w[ii - 2] << 45) | (w[ii - 2] >> 19)))
            + w[ii - 7]
            + ((w[ii - 15] >> 7) ^ ((w[ii - 15] << 56) | (w[ii - 15] >> 8)) ^ ((w[ii - 15] << 63) | (w[ii - 15] >> 1)))
            + w[ii - 16];
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];
    for ( jj = 0; jj < 80; ++jj )
    {
      t1 = w[jj]
         + SHA512_K[jj]
         + (g & ~e ^ f & e)
         + (((e << 23) | (e >> 41)) ^ ((e << 46) | (e >> 18)) ^ ((e << 50) | (e >> 14)))
         + h;
      t2 = (c & b ^ c & a ^ b & a) + (((a << 25) | (a >> 39)) ^ ((a << 30) | (a >> 34)) ^ ((a << 36) | (a >> 28)));
      h = g;
      g = f;
      f = e;
      e = t1 + d;
      d = c;
      c = b;
      b = a;
      a = t2 + t1;
    }
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }
  for ( kk = 0; kk < 8; ++kk )
  {
    for ( mm = 0; mm < 8; ++mm )
      out[8 * kk + mm] = H[kk] >> (56 - 8 * (unsigned __int8)mm);
  }
}
