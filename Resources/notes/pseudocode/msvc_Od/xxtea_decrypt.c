void __fastcall xxtea_decrypt(unsigned int *v, int n, const unsigned int *key)
{
  unsigned int v3; // eax
  int p; // [rsp+0h] [rbp-38h]
  unsigned int y; // [rsp+4h] [rbp-34h]
  unsigned int z; // [rsp+8h] [rbp-30h]
  unsigned int za; // [rsp+8h] [rbp-30h]
  unsigned int sum; // [rsp+Ch] [rbp-2Ch]
  int rounds; // [rsp+10h] [rbp-28h]
  unsigned int e; // [rsp+18h] [rbp-20h]
  unsigned int v11; // [rsp+1Ch] [rbp-1Ch]

  rounds = 52 / n + 6;
  sum = -1640531527 * rounds;
  y = *v;
  do
  {
    e = (sum >> 2) & 3;
    for ( p = n - 1; p > 0; --p )
    {
      z = v[p - 1];
      v3 = v[p] - (((z ^ key[e ^ p & 3]) + (y ^ sum)) ^ (((16 * z) ^ (y >> 3)) + ((4 * y) ^ (z >> 5))));
      v[p] = v3;
      y = v3;
    }
    za = v[n - 1];
    v11 = *v - (((za ^ key[e ^ p & 3]) + (y ^ sum)) ^ (((16 * za) ^ (y >> 3)) + ((4 * y) ^ (za >> 5))));
    *v = v11;
    y = v11;
    sum += 1640531527;
    --rounds;
  }
  while ( rounds != 0 );
}
