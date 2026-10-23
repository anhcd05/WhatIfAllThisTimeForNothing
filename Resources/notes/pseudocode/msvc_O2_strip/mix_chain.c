// mix_chain = sub_140003D40 (bản strip, IDA không có tên hàm)
unsigned __int64 __fastcall sub_140003D40(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  char i; // r9
  char v4; // r8

  result = 0;
  for ( i = 66; result < a2; ++result )
  {
    v4 = i ^ (__ROL1__(*(_BYTE *)(result + a1) ^ (result + 90), 3) + 19);
    *(_BYTE *)(result + a1) = v4;
    i = v4;
  }
  return result;
}
