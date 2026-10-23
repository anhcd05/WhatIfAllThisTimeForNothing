void __fastcall mix_chain(unsigned __int8 *b, unsigned __int64 n)
{
  unsigned __int8 prev; // [rsp+1h] [rbp-17h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  prev = 66;
  for ( i = 0; i < n; ++i )
  {
    prev ^= (((int)(unsigned __int8)((i + 90) ^ b[i]) >> 5) | (8 * ((i + 90) ^ b[i]))) + 19;
    b[i] = prev;
  }
}
