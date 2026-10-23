void __fastcall tea_encrypt(unsigned int *v, const unsigned int *k)
{
  unsigned int v2; // r8d
  int v3; // r10d
  unsigned int v4; // eax
  __int64 i; // r11

  v2 = *v;
  v3 = 0;
  v4 = v[1];
  for ( i = 32; i != 0; --i )
  {
    v3 -= 1640531527;
    v2 += (v3 + v4) ^ (*k + 16 * v4) ^ (k[1] + (v4 >> 5));
    v4 += (v3 + v2) ^ (k[2] + 16 * v2) ^ (k[3] + (v2 >> 5));
  }
  *v = v2;
  v[1] = v4;
}
