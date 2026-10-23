// hex_encode = sub_140002A60 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002A60(unsigned __int8 *a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r9
  __int64 i; // r10
  unsigned __int64 v5; // rax

  if ( a2 != 0 )
  {
    v3 = a3;
    for ( i = a2; i != 0; --i )
    {
      v3 += 2;
      v5 = (unsigned __int64)*a1++ >> 4;
      *(_BYTE *)(v3 - 2) = a0123456789abcd[v5];
      *(_BYTE *)(v3 - 1) = a0123456789abcd[*(a1 - 1) & 0xF];
    }
  }
  *(_BYTE *)(2 * a2 + a3) = 0;
  return 2 * a2;
}
