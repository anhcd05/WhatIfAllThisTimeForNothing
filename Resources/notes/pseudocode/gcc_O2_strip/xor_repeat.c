// xor_repeat = sub_2840 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2840(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 v5; // rsi
  __int64 result; // rax

  if ( a2 != 0 )
  {
    v5 = 0;
    do
    {
      result = *(unsigned __int8 *)(a3 + v5 % a4);
      *(_BYTE *)(a1 + v5++) ^= result;
    }
    while ( a2 != v5 );
  }
  return result;
}
