// hex_encode = sub_140001BF0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140001BF0(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 i; // rax

  if ( a2 != 0 )
  {
    for ( i = 0; i != a2; ++i )
    {
      *(_BYTE *)(a3 + 2 * i) = a0123456789abcd[*(_BYTE *)(a1 + i) >> 4];
      *(_BYTE *)(a3 + 2 * i + 1) = a0123456789abcd[*(_BYTE *)(a1 + i) & 0xF];
    }
  }
  *(_BYTE *)(a3 + 2 * a2) = 0;
  return 2 * a2;
}
