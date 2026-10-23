unsigned __int64 __fastcall a85_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  unsigned __int8 b[4]; // [rsp+20h] [rbp-58h] BYREF
  unsigned __int64 o; // [rsp+28h] [rbp-50h]
  unsigned __int64 i; // [rsp+30h] [rbp-48h]
  int k; // [rsp+38h] [rbp-40h]
  unsigned int v; // [rsp+3Ch] [rbp-3Ch]
  int j; // [rsp+40h] [rbp-38h]
  unsigned int v10; // [rsp+44h] [rbp-34h]
  unsigned __int64 r; // [rsp+48h] [rbp-30h]
  char t[8]; // [rsp+50h] [rbp-28h] BYREF
  _BYTE Src[8]; // [rsp+58h] [rbp-20h] BYREF

  o = 0;
  for ( i = 0; i + 4 <= n; i += 4LL )
  {
    v = _byteswap_ulong(*(_DWORD *)&in[i]);
    if ( v != 0 )
    {
      for ( k = 4; k >= 0; --k )
      {
        t[k] = v % 0x55 + 33;
        v /= 0x55u;
      }
      memmove(a1: &out[o], Src: t, Size: 5u);
      o += 5LL;
    }
    else
    {
      out[o++] = 122;
    }
  }
  if ( i < n )
  {
    b[0] = 0;
    b[1] = 0;
    b[2] = 0;
    b[3] = 0;
    r = n - i;
    memmove(a1: b, Src: &in[i], Size: n - i);
    v10 = _byteswap_ulong(*(unsigned int *)b);
    for ( j = 4; j >= 0; --j )
    {
      Src[j] = v10 % 0x55 + 33;
      v10 /= 0x55u;
    }
    memmove(a1: &out[o], Src, Size: r + 1);
    o += r + 1;
  }
  out[o] = 0;
  return o;
}
