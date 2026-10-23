__int64 __fastcall xxtea_encrypt(_DWORD *a1, int a2, __int64 a3)
{
  unsigned int *v3; // rax
  unsigned int *v4; // rax
  __int64 result; // rax
  unsigned int v6; // [rsp+1Ch] [rbp-1Ch]
  int v7; // [rsp+20h] [rbp-18h]
  unsigned int v8; // [rsp+28h] [rbp-10h]
  int j; // [rsp+2Ch] [rbp-Ch]
  unsigned int v10; // [rsp+30h] [rbp-8h]
  unsigned int i; // [rsp+34h] [rbp-4h]

  v10 = 0;
  v8 = 52 / a2 + 6;
  for ( i = a1[a2 - 1]; ; i = *v4 )
  {
    result = v8--;
    if ( (int)result <= 0 )
      break;
    v10 -= 1640531527;
    v7 = (v10 >> 2) & 3;
    for ( j = 0; j < a2 - 1; ++j )
    {
      v6 = a1[j + 1];
      v3 = &a1[j];
      *v3 += ((v6 ^ v10) + (i ^ *(_DWORD *)(4LL * (v7 ^ j & 3u) + a3)))
           ^ (((4 * v6) ^ (i >> 5)) + ((v6 >> 3) ^ (16 * i)));
      i = *v3;
    }
    v4 = &a1[a2 - 1];
    *v4 += ((*a1 ^ v10) + (i ^ *(_DWORD *)(4LL * (v7 ^ j & 3u) + a3)))
         ^ (((4 * *a1) ^ (i >> 5)) + ((*a1 >> 3) ^ (16 * i)));
  }
  return result;
}
