unsigned __int64 __fastcall hex_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  char *v3; // r9
  unsigned __int64 i; // r10
  unsigned __int64 v5; // rax

  if ( n != 0 )
  {
    v3 = out;
    for ( i = n; i != 0; --i )
    {
      v3 += 2;
      v5 = (unsigned __int64)*in++ >> 4;
      *(v3 - 2) = H[v5];
      *(v3 - 1) = H[*(in - 1) & 0xF];
    }
  }
  out[2 * n] = 0;
  return 2 * n;
}
