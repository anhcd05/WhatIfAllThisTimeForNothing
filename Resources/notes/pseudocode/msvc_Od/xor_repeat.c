void __fastcall xor_repeat(unsigned __int8 *b, unsigned __int64 n, const unsigned __int8 *key, unsigned __int64 kl)
{
  unsigned __int64 i; // [rsp+0h] [rbp-18h]

  for ( i = 0; i < n; ++i )
    b[i] ^= key[i % kl];
}
