// b32_encode = sub_140001FE0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140001FE0(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 result; // rax
  unsigned __int64 i; // r10
  int v5; // r9d
  unsigned __int64 v6; // r11

  result = 0;
  i = 0;
  v5 = 0;
  v6 = 0;
  if ( a2 != 0 )
  {
    do
    {
      v5 += 8;
      for ( i = *(unsigned __int8 *)(v6 + a1) | (i << 8); v5 >= 5; ++result )
      {
        v5 -= 5;
        *(_BYTE *)(result + a3) = aAbcdefghijklmn[(i >> v5) & 0x1F];
      }
      ++v6;
    }
    while ( v6 < a2 );
    if ( v5 > 0 )
    {
      *(_BYTE *)(result + a3) = aAbcdefghijklmn[(i << (5 - (unsigned __int8)v5)) & 0x1F];
      ++result;
    }
  }
  for ( ; (result & 7) != 0; ++result )
    *(_BYTE *)(result + a3) = 61;
  *(_BYTE *)(result + a3) = 0;
  return result;
}
