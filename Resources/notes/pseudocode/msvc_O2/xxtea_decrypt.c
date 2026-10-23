void __fastcall xxtea_decrypt(unsigned int *v, int n, const unsigned int *key)
{
  unsigned int v3; // r9d
  unsigned int *v6; // r14
  int v7; // r13d
  int v8; // eax
  unsigned int v9; // edi
  int v10; // ebx
  __int64 v11; // r11
  unsigned int v12; // ebp
  unsigned int *v13; // rsi
  unsigned int v14; // r10d
  int v15; // edx
  __int64 v16; // rax
  unsigned int v17; // ecx
  unsigned int v18; // r9d
  int v19; // r8d
  int v20; // eax
  int v21; // r9d
  unsigned int v22; // r8d
  int v23; // [rsp+38h] [rbp+10h]

  v3 = *v;
  v6 = &v[n];
  v7 = 52 / n + 6;
  v8 = n - 1;
  v9 = -1640531527 * v7;
  v23 = n - 1;
  do
  {
    v10 = v8;
    v11 = (v9 >> 2) & 3;
    if ( v8 > 0 )
    {
      v12 = *(v6 - 1);
      v13 = v6 - 1;
      do
      {
        v14 = *--v13;
        v15 = ((4 * v3) ^ (v14 >> 5)) + ((v3 >> 3) ^ (16 * v14));
        v16 = v10-- & 3;
        v17 = (v9 ^ v3) + (v14 ^ key[v11 ^ v16]);
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
    v8 = v23;
    *v -= (v21 + (*(v6 - 1) ^ key[v11 ^ v10 & 3])) ^ v22;
    v3 = *v;
    --v7;
  }
  while ( v7 != 0 );
}
