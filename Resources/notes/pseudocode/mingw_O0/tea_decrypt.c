__int64 __fastcall tea_decrypt(unsigned int *a1, _DWORD *a2)
{
  int i; // [rsp+10h] [rbp-10h]
  int v4; // [rsp+14h] [rbp-Ch]
  unsigned int v5; // [rsp+18h] [rbp-8h]
  unsigned int v6; // [rsp+1Ch] [rbp-4h]

  v6 = *a1;
  v5 = a1[1];
  v4 = -957401312;
  for ( i = 0; i <= 31; ++i )
  {
    v5 -= (v6 + v4) ^ (16 * v6 + a2[2]) ^ ((v6 >> 5) + a2[3]);
    v6 -= (v5 + v4) ^ (16 * v5 + *a2) ^ ((v5 >> 5) + a2[1]);
    v4 += 1640531527;
  }
  *a1 = v6;
  a1[1] = v5;
  return v5;
}
