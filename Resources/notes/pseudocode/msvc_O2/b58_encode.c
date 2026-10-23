unsigned __int64 __fastcall b58_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  unsigned __int64 v6; // rdi
  unsigned __int64 v7; // rsi
  unsigned __int64 v8; // rbx
  unsigned __int64 i; // r9
  int v10; // ecx
  unsigned __int64 j; // r8
  int v12; // ecx
  unsigned __int8 buf[304]; // [rsp+20h] [rbp-158h] BYREF

  v6 = 0;
  v7 = 0;
  v8 = 0;
  memset(a1: buf, Val: 0, Size: 0x12Cu);
  if ( n != 0 )
  {
    do
    {
      if ( in[v7] != 0 )
        break;
      ++v7;
    }
    while ( v7 < n );
  }
  for ( i = v7; i < n; ++i )
  {
    v10 = in[i];
    for ( j = 0; j < v8; v10 = v12 / 58 )
    {
      v12 = (buf[j] << 8) + v10;
      buf[j++] = v12 % 58;
    }
    for ( ; v10 != 0; v10 /= 58 )
      buf[v8++] = v10 % 58;
  }
  if ( v7 != 0 )
  {
    memset(out, 49, v7);
    v6 = v7;
  }
  for ( ; v8 != 0; --v8 )
    out[v6++] = T_2[buf[v8 - 1]];
  out[v6] = 0;
  return v6;
}
