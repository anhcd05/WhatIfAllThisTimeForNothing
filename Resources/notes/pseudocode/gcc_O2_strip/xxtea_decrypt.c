// xxtea_decrypt = sub_31F0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_31F0(_DWORD *a1, int a2, __int64 a3)
{
  unsigned int *v6; // rbx
  _DWORD *v7; // rbp
  unsigned int v8; // r8d
  __int64 result; // rax
  int v10; // r13d
  unsigned int v11; // esi
  _DWORD *v12; // rdi
  int v13; // edx
  unsigned int v14; // r12d

  v6 = &a1[a2 - 1];
  v7 = &a1[a2];
  v8 = -1640531527 * (52 / a2 + 6);
  LODWORD(result) = *a1;
  do
  {
    v10 = (v8 >> 2) & 3;
    if ( a2 <= 1 )
    {
      LOBYTE(v13) = a2 - 1;
    }
    else
    {
      v11 = *v6;
      v12 = v7;
      v13 = a2 - 1;
      do
      {
        v14 = v11;
        v11 = *(v12 - 2);
        --v12;
        LODWORD(result) = v14
                        - ((((4 * result) ^ (v11 >> 5)) + ((16 * v11) ^ ((unsigned int)result >> 3)))
                         ^ ((v11 ^ *(_DWORD *)(a3 + 4LL * (((unsigned __int8)v10 ^ (unsigned __int8)v13) & 3)))
                          + (result ^ v8)));
        *v12 = result;
        --v13;
      }
      while ( v13 != 0 );
    }
    result = *a1
           - ((((4 * (_DWORD)result) ^ (*v6 >> 5)) + ((16 * *v6) ^ ((unsigned int)result >> 3)))
            ^ ((*v6 ^ *(_DWORD *)(a3 + 4LL * (((unsigned __int8)v10 ^ (unsigned __int8)v13) & 3)))
             + ((unsigned int)result ^ v8)));
    *a1 = result;
    v8 += 1640531527;
  }
  while ( v8 != 0 );
  return result;
}
