void __fastcall xor_single(unsigned __int8 *b, unsigned __int64 n, unsigned __int8 k)
{
  unsigned __int64 i; // [rsp+0h] [rbp-18h]

  for ( i = 0; i < n; ++i )
    b[i] ^= k;
}
