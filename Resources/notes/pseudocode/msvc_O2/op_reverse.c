void __fastcall op_reverse(unsigned __int8 *b, unsigned __int64 n)
{
  unsigned __int64 v2; // r9
  unsigned __int8 *v3; // r8
  unsigned __int8 v4; // al
  unsigned __int8 v5; // dl

  v2 = n >> 1;
  if ( n >> 1 != 0 )
  {
    v3 = &b[n - 1];
    do
    {
      v4 = *v3--;
      v5 = *b;
      *b++ = v4;
      v3[1] = v5;
      --v2;
    }
    while ( v2 != 0 );
  }
}
