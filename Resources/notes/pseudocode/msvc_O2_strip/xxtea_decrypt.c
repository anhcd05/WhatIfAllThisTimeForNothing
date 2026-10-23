// xxtea_decrypt = sub_140006890 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140006890(unsigned int *a1, int a2, __int64 a3)
{
  unsigned int v3; // r9d
  unsigned int *v6; // r14
  int v7; // r13d
  __int64 result; // rax
  unsigned int v9; // edi
  int v10; // ebx
  __int64 v11; // r11
  unsigned int v12; // ebp
  unsigned int *v13; // rsi
  unsigned int v14; // r10d
  int v15; // edx
  __int64 v16; // rax
  int v17; // ecx
  unsigned int v18; // r9d
  int v19; // r8d
  int v20; // eax
  int v21; // r9d
  int v22; // r8d
  unsigned int v23; // [rsp+38h] [rbp+10h]

  v3 = *a1;
  v6 = &a1[a2];
  v7 = 52 / a2 + 6;
  LODWORD(result) = a2 - 1;
  v9 = -1640531527 * v7;
  v23 = a2 - 1;
  do
  {
    v10 = result;
    v11 = (v9 >> 2) & 3;
    if ( (int)result > 0 )
    {
      v12 = *(v6 - 1);
      v13 = v6 - 1;
      do
      {
        v14 = *--v13;
        v15 = ((4 * v3) ^ (v14 >> 5)) + ((v3 >> 3) ^ (16 * v14));
        v16 = v10-- & 3;
        v17 = (v9 ^ v3) + (v14 ^ *(_DWORD *)(a3 + 4 * (v11 ^ v16)));
        v18 = v12;
        v12 = v14;
        v3 = v18 - (v17 ^ v15);
        v13[1] = v3;
      }
      while ( v10 > 0 );
    }
    v19 = (v3 >> 3) ^ (16 * *(v6 - 1));
    v20 = 4 * v3;
    v21 = v9 ^ v3;
    v9 += 1640531527;
    v22 = (v20 ^ (*(v6 - 1) >> 5)) + v19;
    result = v23;
    *a1 -= (v21 + (*(v6 - 1) ^ *(_DWORD *)(a3 + 4 * (v11 ^ v10 & 3)))) ^ v22;
    v3 = *a1;
    --v7;
  }
  while ( v7 != 0 );
  return result;
}
