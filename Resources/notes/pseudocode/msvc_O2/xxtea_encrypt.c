void __fastcall xxtea_encrypt(unsigned int *v, int n, const unsigned int *key)
{
  unsigned int v3; // ebx
  unsigned int v4; // r11d
  int v6; // r12d
  int v7; // esi
  int v8; // edi
  __int64 v9; // rax
  unsigned int v10; // ebp
  unsigned int *v11; // r14
  unsigned int v12; // r10d
  __int64 v13; // rcx
  unsigned int *v14; // [rsp+30h] [rbp+8h]

  v3 = 0;
  v4 = v[n - 1];
  v6 = n - 1;
  v7 = 52 / n + 6;
  if ( v7 > 0 )
  {
    v14 = &v[n - 1];
    do
    {
      v3 -= 1640531527;
      --v7;
      v8 = 0;
      v9 = (v3 >> 2) & 3;
      if ( v6 > 0 )
      {
        v10 = *v;
        v11 = v;
        do
        {
          v12 = v11[1];
          ++v11;
          v13 = v9 ^ v8++ & 3;
          v4 = v10 + ((((16 * v4) ^ (v12 >> 3)) + ((v4 >> 5) ^ (4 * v12))) ^ ((v3 ^ v12) + (key[v13] ^ v4)));
          v10 = v12;
          *(v11 - 1) = v4;
        }
        while ( v8 < v6 );
      }
      *v14 += ((v3 ^ *v) + (v4 ^ key[v9 ^ v8 & 3])) ^ (((16 * v4) ^ (*v >> 3)) + ((v4 >> 5) ^ (4 * *v)));
      v4 = *v14;
    }
    while ( v7 > 0 );
  }
}
