// xor_repeat = sub_140005D10 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140005D10(__int64 a1, unsigned __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 i; // r10
  __int64 result; // rax

  for ( i = 0; i < a2; ++i )
  {
    result = *(unsigned __int8 *)(i % a4 + a3);
    *(_BYTE *)(i + a1) ^= result;
  }
  return result;
}
