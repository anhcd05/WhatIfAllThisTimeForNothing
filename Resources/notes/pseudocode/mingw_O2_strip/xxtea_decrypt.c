// xxtea_decrypt = sub_140002850 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002850(_DWORD *a1, int a2, __int64 a3)
{
  unsigned int *v4; // rdi
  _DWORD *v5; // rbp
  unsigned int v6; // r11d
  __int64 result; // rax
  int v8; // r13d
  unsigned int v9; // r9d
  _DWORD *v10; // r10
  int v11; // edx
  unsigned int v12; // r12d

  v4 = &a1[a2 - 1];
  v5 = &a1[a2];
  v6 = -1640531527 * (52 / a2 + 6);
  LODWORD(result) = *a1;
  do
  {
    v8 = (v6 >> 2) & 3;
    if ( a2 <= 1 )
    {
      LOBYTE(v11) = a2 - 1;
    }
    else
    {
      v9 = *v4;
      v10 = v5;
      v11 = a2 - 1;
      do
      {
        v12 = v9;
        v9 = *(v10 - 2);
        --v10;
        LODWORD(result) = v12
                        - ((((4 * result) ^ (v9 >> 5)) + ((16 * v9) ^ ((unsigned int)result >> 3)))
                         ^ ((v9 ^ *(_DWORD *)(a3 + 4LL * (((unsigned __int8)v8 ^ (unsigned __int8)v11) & 3)))
                          + (result ^ v6)));
        *v10 = result;
        --v11;
      }
      while ( v11 != 0 );
    }
    result = *a1
           - ((((4 * (_DWORD)result) ^ (*v4 >> 5)) + ((16 * *v4) ^ ((unsigned int)result >> 3)))
            ^ ((*v4 ^ *(_DWORD *)(a3 + 4LL * (((unsigned __int8)v8 ^ (unsigned __int8)v11) & 3)))
             + ((unsigned int)result ^ v6)));
    *a1 = result;
    v6 += 1640531527;
  }
  while ( v6 != 0 );
  return result;
}
