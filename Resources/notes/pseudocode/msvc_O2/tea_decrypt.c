void __fastcall tea_decrypt(unsigned int *v, const unsigned int *k)
{
  unsigned int v2; // r8d
  unsigned int v3; // eax
  int v4; // r10d
  unsigned int v5; // ebx
  __int64 v6; // r11
  unsigned int v7; // edi
  int v8; // esi
  unsigned int v9; // ebp
  int v10; // edx

  v2 = *v;
  v3 = v[1];
  v4 = -957401312;
  v5 = k[2];
  v6 = 32;
  v7 = k[3];
  v8 = *k;
  v9 = k[1];
  do
  {
    v3 -= (v4 + v2) ^ (v5 + 16 * v2) ^ (v7 + (v2 >> 5));
    v10 = (v4 + v3) ^ (v8 + 16 * v3) ^ (v9 + (v3 >> 5));
    v4 += 1640531527;
    v2 -= v10;
    --v6;
  }
  while ( v6 != 0 );
  *v = v2;
  v[1] = v3;
}
