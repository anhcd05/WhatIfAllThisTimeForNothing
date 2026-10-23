// tea_encrypt = sub_140005C80 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140005C80(unsigned int *a1, _DWORD *a2)
{
  unsigned int v2; // r8d
  int v3; // r10d
  __int64 result; // rax
  __int64 i; // r11

  v2 = *a1;
  v3 = 0;
  LODWORD(result) = a1[1];
  for ( i = 32; i != 0; --i )
  {
    v3 -= 1640531527;
    v2 += (v3 + result) ^ (*a2 + 16 * result) ^ (a2[1] + ((unsigned int)result >> 5));
    result = ((v3 + v2) ^ (a2[2] + 16 * v2) ^ (a2[3] + (v2 >> 5))) + (unsigned int)result;
  }
  *a1 = v2;
  a1[1] = result;
  return result;
}
