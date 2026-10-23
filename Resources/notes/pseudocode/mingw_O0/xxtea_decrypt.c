__int64 __fastcall xxtea_decrypt(unsigned int *a1, int a2, __int64 a3)
{
  unsigned int *v3; // rax
  __int64 result; // rax
  unsigned int v5; // [rsp+4h] [rbp-1Ch]
  unsigned int v6; // [rsp+4h] [rbp-1Ch]
  int v7; // [rsp+8h] [rbp-18h]
  int v8; // [rsp+10h] [rbp-10h]
  int i; // [rsp+14h] [rbp-Ch]
  unsigned int v10; // [rsp+18h] [rbp-8h]
  unsigned int v11; // [rsp+1Ch] [rbp-4h]

  v8 = 52 / a2 + 6;
  v10 = -1640531527 * v8;
  v11 = *a1;
  do
  {
    v7 = (v10 >> 2) & 3;
    for ( i = a2 - 1; i > 0; --i )
    {
      v5 = a1[i - 1];
      v3 = &a1[i];
      *v3 -= ((v11 ^ v10) + (v5 ^ *(_DWORD *)(4LL * (v7 ^ i & 3u) + a3)))
           ^ (((4 * v11) ^ (v5 >> 5)) + ((v11 >> 3) ^ (16 * v5)));
      v11 = *v3;
    }
    v6 = a1[a2 - 1];
    *a1 -= (((4 * v11) ^ (v6 >> 5)) + ((v11 >> 3) ^ (16 * v6)))
         ^ ((v11 ^ v10) + (v6 ^ *(_DWORD *)(4LL * (v7 ^ i & 3u) + a3)));
    v11 = *a1;
    result = 2654435769LL;
    v10 += 1640531527;
    --v8;
  }
  while ( v8 != 0 );
  return result;
}
