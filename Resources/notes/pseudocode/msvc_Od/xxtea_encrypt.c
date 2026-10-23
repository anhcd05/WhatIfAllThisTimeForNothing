void __fastcall xxtea_encrypt(unsigned int *v, int n, const unsigned int *key)
{
  int p; // [rsp+0h] [rbp-38h]
  unsigned int z; // [rsp+4h] [rbp-34h]
  unsigned int y; // [rsp+8h] [rbp-30h]
  unsigned int sum; // [rsp+Ch] [rbp-2Ch]
  int rounds; // [rsp+10h] [rbp-28h]
  unsigned int v8; // [rsp+14h] [rbp-24h]
  unsigned int e; // [rsp+18h] [rbp-20h]
  unsigned int v10; // [rsp+1Ch] [rbp-1Ch]
  int v11; // [rsp+20h] [rbp-18h]

  sum = 0;
  rounds = 52 / n + 6;
  for ( z = v[n - 1]; ; z = v10 )
  {
    v11 = rounds--;
    if ( v11 <= 0 )
      break;
    sum -= 1640531527;
    e = (sum >> 2) & 3;
    for ( p = 0; p < n - 1; ++p )
    {
      y = v[p + 1];
      v8 = (((z ^ key[e ^ p & 3]) + (y ^ sum)) ^ (((16 * z) ^ (y >> 3)) + ((4 * y) ^ (z >> 5)))) + v[p];
      v[p] = v8;
      z = v8;
    }
    v10 = (((z ^ key[e ^ p & 3]) + (*v ^ sum)) ^ (((16 * z) ^ (*v >> 3)) + ((4 * *v) ^ (z >> 5)))) + v[n - 1];
    v[n - 1] = v10;
  }
}
