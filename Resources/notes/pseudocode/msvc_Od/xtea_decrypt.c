void __fastcall xtea_decrypt(unsigned int *v, const unsigned int *k)
{
  unsigned int sum; // [rsp+0h] [rbp-28h]
  unsigned int v0; // [rsp+4h] [rbp-24h]
  unsigned int v1; // [rsp+8h] [rbp-20h]
  int i; // [rsp+Ch] [rbp-1Ch]

  v0 = *v;
  v1 = v[1];
  sum = -957401312;
  for ( i = 0; i < 32; ++i )
  {
    v1 -= (k[(sum >> 11) & 3] + sum) ^ (v0 + ((v0 >> 5) ^ (16 * v0)));
    sum += 1640531527;
    v0 -= (k[sum & 3] + sum) ^ (v1 + ((v1 >> 5) ^ (16 * v1)));
  }
  *v = v0;
  v[1] = v1;
}
