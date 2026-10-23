__int64 __fastcall xxtea_encrypt(unsigned int *a1, int a2, __int64 a3)
{
  char v3; // r12
  __int64 result; // rax
  unsigned int v6; // esi
  unsigned int *v8; // r15
  __int64 v9; // r13
  unsigned int v10; // edx
  unsigned __int8 v11; // r8
  int v12; // r9d
  __int64 v13; // r12
  unsigned int v14; // r10d
  __int64 v15; // rax
  unsigned int v16; // r15d
  unsigned int *v17; // [rsp+0h] [rbp-58h]

  v3 = a2;
  result = (unsigned int)(52 / a2);
  if ( (int)result >= -5 )
  {
    v6 = 0;
    v8 = &a1[a2 - 1];
    v9 = (unsigned int)(a2 - 1);
    v10 = *v8;
    v11 = v3 - 1;
    v12 = -1640531527 * result - 1253254570;
    do
    {
      v6 -= 1640531527;
      v13 = (v6 >> 2) & 3;
      if ( a2 > 1 )
      {
        v17 = v8;
        v14 = *a1;
        v15 = 0;
        do
        {
          v16 = v14;
          v14 = a1[v15 + 1];
          v10 = ((((16 * v10) ^ (v14 >> 3)) + ((4 * v14) ^ (v10 >> 5)))
               ^ ((v14 ^ v6) + (v10 ^ *(_DWORD *)(a3 + 4LL * (((v6 >> 2) & 3 ^ (unsigned __int8)v15) & 3)))))
              + v16;
          a1[v15++] = v10;
        }
        while ( v15 != v9 );
        v8 = v17;
        v13 = (v11 ^ (unsigned __int8)(v6 >> 2)) & 3;
      }
      result = *v8
             + (((v6 ^ *a1) + (*(_DWORD *)(a3 + 4 * v13) ^ v10)) ^ (((4 * *a1) ^ (v10 >> 5)) + ((16 * v10) ^ (*a1 >> 3))));
      *v8 = result;
      v10 = result;
    }
    while ( v6 != v12 );
  }
  return result;
}
