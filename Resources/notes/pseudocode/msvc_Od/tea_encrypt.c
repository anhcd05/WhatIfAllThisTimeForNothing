void __fastcall tea_encrypt(unsigned int *v, const unsigned int *k)
{
  unsigned int v0; // [rsp+0h] [rbp-28h]
  unsigned int v1; // [rsp+4h] [rbp-24h]
  unsigned int sum; // [rsp+8h] [rbp-20h]
  int i; // [rsp+Ch] [rbp-1Ch]

  v0 = *v;
  v1 = v[1];
  sum = 0;
  for ( i = 0; i < 32; ++i )
  {
    sum -= 1640531527;
    v0 += (k[1] + (v1 >> 5)) ^ (sum + v1) ^ (*k + 16 * v1);
    v1 += (k[3] + (v0 >> 5)) ^ (sum + v0) ^ (k[2] + 16 * v0);
  }
  *v = v0;
  v[1] = v1;
}
