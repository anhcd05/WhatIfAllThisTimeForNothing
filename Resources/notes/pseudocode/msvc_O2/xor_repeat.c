void __fastcall xor_repeat(unsigned __int8 *b, unsigned __int64 n, const unsigned __int8 *key, unsigned __int64 kl)
{
  unsigned __int64 i; // r10

  for ( i = 0; i < n; ++i )
    b[i] ^= key[i % kl];
}
