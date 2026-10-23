// xxtea_encrypt = sub_1400069D0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400069D0(_DWORD *a1, int a2, __int64 a3)
{
  unsigned int v3; // ebx
  __int64 result; // rax
  unsigned int v5; // r11d
  int v7; // r12d
  int v8; // esi
  int v9; // edi
  __int64 v10; // rax
  int v11; // ebp
  _DWORD *v12; // r14
  unsigned int v13; // r10d
  __int64 v14; // rcx
  unsigned int *v15; // [rsp+30h] [rbp+8h]

  v3 = 0;
  result = (unsigned int)(52 / a2);
  v5 = a1[a2 - 1];
  v7 = a2 - 1;
  v8 = result + 6;
  if ( (int)result + 6 > 0 )
  {
    v15 = &a1[a2 - 1];
    do
    {
      v3 -= 1640531527;
      --v8;
      v9 = 0;
      v10 = (v3 >> 2) & 3;
      if ( v7 > 0 )
      {
        v11 = *a1;
        v12 = a1;
        do
        {
          v13 = v12[1];
          ++v12;
          v14 = v10 ^ v9++ & 3;
          v5 = v11
             + ((((16 * v5) ^ (v13 >> 3)) + ((v5 >> 5) ^ (4 * v13))) ^ ((v3 ^ v13) + (*(_DWORD *)(a3 + 4 * v14) ^ v5)));
          v11 = v13;
          *(v12 - 1) = v5;
        }
        while ( v9 < v7 );
      }
      result = (v3 ^ *a1) + (v5 ^ *(_DWORD *)(a3 + 4 * (v10 ^ v9 & 3)));
      *v15 += result ^ (((16 * v5) ^ (*a1 >> 3)) + ((v5 >> 5) ^ (4 * *a1)));
      v5 = *v15;
    }
    while ( v8 > 0 );
  }
  return result;
}
