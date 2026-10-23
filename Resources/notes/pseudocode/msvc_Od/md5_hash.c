void __fastcall md5_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  int i; // [rsp+20h] [rbp-1E8h]
  unsigned int B; // [rsp+24h] [rbp-1E4h]
  unsigned int D; // [rsp+28h] [rbp-1E0h]
  unsigned int F; // [rsp+2Ch] [rbp-1DCh]
  unsigned int Fa; // [rsp+2Ch] [rbp-1DCh]
  unsigned int C; // [rsp+30h] [rbp-1D8h]
  unsigned int g; // [rsp+34h] [rbp-1D4h]
  unsigned int a0; // [rsp+38h] [rbp-1D0h] BYREF
  unsigned int b0; // [rsp+3Ch] [rbp-1CCh] BYREF
  unsigned int c0; // [rsp+40h] [rbp-1C8h] BYREF
  unsigned int d0; // [rsp+44h] [rbp-1C4h] BYREF
  unsigned int A; // [rsp+48h] [rbp-1C0h]
  unsigned __int64 off; // [rsp+50h] [rbp-1B8h]
  unsigned __int64 total; // [rsp+58h] [rbp-1B0h]
  unsigned __int64 bits; // [rsp+60h] [rbp-1A8h] BYREF
  unsigned int M[16]; // [rsp+70h] [rbp-198h] BYREF
  unsigned __int8 buf[320]; // [rsp+B0h] [rbp-158h] BYREF

  a0 = 1732584193;
  b0 = -271733879;
  c0 = -1732584194;
  d0 = 271733878;
  total = ((n + 8) / 0x40 + 1) << 6;
  bits = 8 * n;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  memmove(a1: (char *)&M[14] + total, Src: &bits, Size: 8u);
  for ( off = 0; off < total; off += 64LL )
  {
    A = a0;
    B = b0;
    C = c0;
    D = d0;
    memmove(a1: M, Src: &buf[off], Size: 0x40u);
    for ( i = 0; i < 64; ++i )
    {
      if ( i >= 16 )
      {
        if ( i >= 32 )
        {
          if ( i >= 48 )
          {
            F = (~D | B) ^ C;
            g = (7 * (_BYTE)i) & 0xF;
          }
          else
          {
            F = D ^ C ^ B;
            g = (3 * (_BYTE)i + 5) & 0xF;
          }
        }
        else
        {
          F = C & ~D | B & D;
          g = (5 * (_BYTE)i + 1) & 0xF;
        }
      }
      else
      {
        F = D & ~B | C & B;
        g = i;
      }
      Fa = M[g] + MD5_K[i] + A + F;
      A = D;
      D = C;
      C = B;
      B += __ROL4__(Fa, R[i]);
    }
    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;
  }
  memmove(a1: out, Src: &a0, Size: 4u);
  memmove(a1: out + 4, Src: &b0, Size: 4u);
  memmove(a1: out + 8, Src: &c0, Size: 4u);
  memmove(a1: out + 12, Src: &d0, Size: 4u);
}
