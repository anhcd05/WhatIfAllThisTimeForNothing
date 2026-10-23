// tea_decrypt = sub_140005BE0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140005BE0(unsigned int *a1, int *a2)
{
  unsigned int v2; // r8d
  __int64 result; // rax
  int v4; // r10d
  int v5; // ebx
  __int64 v6; // r11
  int v7; // edi
  int v8; // esi
  int v9; // ebp
  int v10; // edx

  v2 = *a1;
  LODWORD(result) = a1[1];
  v4 = -957401312;
  v5 = a2[2];
  v6 = 32;
  v7 = a2[3];
  v8 = *a2;
  v9 = a2[1];
  do
  {
    result = (unsigned int)result - ((v4 + v2) ^ (v5 + 16 * v2) ^ (v7 + (v2 >> 5)));
    v10 = (v4 + result) ^ (v8 + 16 * result) ^ (v9 + ((unsigned int)result >> 5));
    v4 += 1640531527;
    v2 -= v10;
    --v6;
  }
  while ( v6 != 0 );
  *a1 = v2;
  a1[1] = result;
  return result;
}
