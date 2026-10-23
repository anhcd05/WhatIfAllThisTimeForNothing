void __fastcall sha1_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  int m; // [rsp+20h] [rbp-318h]
  int jj; // [rsp+24h] [rbp-314h]
  unsigned int b; // [rsp+28h] [rbp-310h]
  int j; // [rsp+2Ch] [rbp-30Ch]
  unsigned int c; // [rsp+30h] [rbp-308h]
  unsigned int d; // [rsp+34h] [rbp-304h]
  int ii; // [rsp+38h] [rbp-300h]
  int i; // [rsp+3Ch] [rbp-2FCh]
  unsigned int a; // [rsp+40h] [rbp-2F8h]
  unsigned int f; // [rsp+44h] [rbp-2F4h]
  unsigned int k; // [rsp+48h] [rbp-2F0h]
  _BYTE h0[20]; // [rsp+4Ch] [rbp-2ECh]
  unsigned int e; // [rsp+60h] [rbp-2D8h]
  unsigned __int64 off; // [rsp+68h] [rbp-2D0h]
  unsigned int tmp; // [rsp+70h] [rbp-2C8h]
  unsigned __int64 total; // [rsp+78h] [rbp-2C0h]
  unsigned __int64 bits; // [rsp+80h] [rbp-2B8h]
  unsigned int h[6]; // [rsp+88h] [rbp-2B0h]
  unsigned int w[80]; // [rsp+A0h] [rbp-298h]
  unsigned __int8 buf[320]; // [rsp+1E0h] [rbp-158h] BYREF

  *(_DWORD *)h0 = 1732584193;
  *(_DWORD *)&h0[4] = -271733879;
  *(_DWORD *)&h0[8] = -1732584194;
  *(_DWORD *)&h0[12] = 271733878;
  *(_DWORD *)&h0[16] = -1009589776;
  total = ((n + 8) / 0x40 + 1) << 6;
  bits = 8 * n;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  for ( i = 0; i < 8; ++i )
    buf[total - 1 - i] = bits >> (8 * (unsigned __int8)i);
  for ( off = 0; off < total; off += 64LL )
  {
    for ( j = 0; j < 16; ++j )
      w[j] = buf[4 * j + 3 + off]
           | (buf[4 * j + 2 + off] << 8)
           | (buf[4 * j + 1 + off] << 16)
           | (buf[4 * j + off] << 24);
    for ( m = 16; m < 80; ++m )
      w[m] = ((w[m - 16] ^ w[m - 14] ^ w[m - 8] ^ w[m - 3]) >> 31) | (2 * (w[m - 16] ^ w[m - 14] ^ w[m - 8] ^ w[m - 3]));
    a = *(_DWORD *)h0;
    b = *(_DWORD *)&h0[4];
    c = *(_DWORD *)&h0[8];
    d = *(_DWORD *)&h0[12];
    e = *(_DWORD *)&h0[16];
    for ( ii = 0; ii < 80; ++ii )
    {
      if ( ii >= 20 )
      {
        if ( ii >= 40 )
        {
          if ( ii >= 60 )
          {
            f = d ^ c ^ b;
            k = -899497514;
          }
          else
          {
            f = d & c | d & b | c & b;
            k = -1894007588;
          }
        }
        else
        {
          f = d ^ c ^ b;
          k = 1859775393;
        }
      }
      else
      {
        f = d & ~b | c & b;
        k = 1518500249;
      }
      tmp = w[ii] + k + e + f + ((a >> 27) | (32 * a));
      e = d;
      d = c;
      c = (b >> 2) | (b << 30);
      b = a;
      a = tmp;
    }
    *(_DWORD *)h0 += a;
    *(_DWORD *)&h0[4] += b;
    *(_DWORD *)&h0[8] += c;
    *(_DWORD *)&h0[12] += d;
    *(_DWORD *)&h0[16] += e;
  }
  qmemcpy(h, h0, 20);
  for ( jj = 0; jj < 5; ++jj )
  {
    out[4 * jj] = HIBYTE(h[jj]);
    out[4 * jj + 1] = BYTE2(h[jj]);
    out[4 * jj + 2] = BYTE1(h[jj]);
    out[4 * jj + 3] = h[jj];
  }
}
