void __fastcall sha256_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  unsigned __int64 v3; // kr00_8
  unsigned __int64 v4; // kr08_8
  unsigned __int64 v5; // kr10_8
  int m; // [rsp+20h] [rbp-2E8h]
  unsigned int a; // [rsp+24h] [rbp-2E4h]
  unsigned int e; // [rsp+28h] [rbp-2E0h]
  int jj; // [rsp+2Ch] [rbp-2DCh]
  int k; // [rsp+30h] [rbp-2D8h]
  int i; // [rsp+34h] [rbp-2D4h]
  int j; // [rsp+38h] [rbp-2D0h]
  int ii; // [rsp+3Ch] [rbp-2CCh]
  unsigned int b; // [rsp+40h] [rbp-2C8h]
  unsigned int c; // [rsp+44h] [rbp-2C4h]
  unsigned int f; // [rsp+48h] [rbp-2C0h]
  unsigned int g; // [rsp+4Ch] [rbp-2BCh]
  unsigned int d; // [rsp+50h] [rbp-2B8h]
  unsigned int h; // [rsp+54h] [rbp-2B4h]
  unsigned __int64 off; // [rsp+58h] [rbp-2B0h]
  unsigned int t1; // [rsp+60h] [rbp-2A8h]
  unsigned int t2; // [rsp+7Ch] [rbp-28Ch]
  unsigned __int64 total; // [rsp+80h] [rbp-288h]
  unsigned __int64 bits; // [rsp+88h] [rbp-280h]
  unsigned int H[8]; // [rsp+90h] [rbp-278h]
  unsigned int w[64]; // [rsp+B0h] [rbp-258h]
  unsigned __int8 buf[320]; // [rsp+1B0h] [rbp-158h] BYREF

  total = ((n + 8) / 0x40 + 1) << 6;
  bits = 8 * n;
  for ( i = 0; i < 8; ++i )
    H[i] = SHA256_H0[i];
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  for ( j = 0; j < 8; ++j )
    buf[total - 1 - j] = bits >> (8 * (unsigned __int8)j);
  for ( off = 0; off < total; off += 64LL )
  {
    for ( k = 0; k < 16; ++k )
      w[k] = buf[4 * k + 3 + off]
           | (buf[4 * k + 2 + off] << 8)
           | (buf[4 * k + 1 + off] << 16)
           | (buf[4 * k + off] << 24);
    for ( m = 16; m < 64; ++m )
    {
      v3 = (unsigned __int64)w[m - 15] << 25;
      v4 = (unsigned __int64)w[m - 15] << 14;
      v5 = (unsigned __int64)w[m - 2] << 15;
      w[m] = ((w[m - 2] >> 10) ^ ((w[m - 2] << 13) | ((unsigned __int64)w[m - 2] >> 19)) ^ (v5 | HIDWORD(v5)))
           + w[m - 7]
           + ((w[m - 15] >> 3) ^ (v4 | HIDWORD(v4)) ^ (v3 | HIDWORD(v3)))
           + w[m - 16];
    }
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];
    for ( ii = 0; ii < 64; ++ii )
    {
      t1 = w[ii]
         + SHA256_K[ii]
         + (g & ~e ^ f & e)
         + (((e << 7) | ((unsigned __int64)e >> 25))
          ^ ((e << 21) | ((unsigned __int64)e >> 11))
          ^ ((e << 26) | ((unsigned __int64)e >> 6)))
         + h;
      t2 = (c & b ^ c & a ^ b & a)
         + (((a << 10) | ((unsigned __int64)a >> 22))
          ^ ((a << 19) | ((unsigned __int64)a >> 13))
          ^ ((a << 30) | ((unsigned __int64)a >> 2)));
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
  for ( jj = 0; jj < 8; ++jj )
  {
    out[4 * jj] = HIBYTE(H[jj]);
    out[4 * jj + 1] = BYTE2(H[jj]);
    out[4 * jj + 2] = BYTE1(H[jj]);
    out[4 * jj + 3] = H[jj];
  }
}
