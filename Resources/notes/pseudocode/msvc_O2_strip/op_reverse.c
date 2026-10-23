// op_reverse = sub_140003EC0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140003EC0(unsigned __int8 *a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r9
  unsigned __int8 *v3; // r8
  __int64 result; // rax
  unsigned __int8 v5; // dl

  v2 = a2 >> 1;
  if ( a2 >> 1 != 0 )
  {
    v3 = &a1[a2 - 1];
    do
    {
      result = *v3--;
      v5 = *a1;
      *a1++ = result;
      v3[1] = v5;
      --v2;
    }
    while ( v2 != 0 );
  }
  return result;
}
