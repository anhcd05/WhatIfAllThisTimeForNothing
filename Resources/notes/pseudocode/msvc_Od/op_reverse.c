void __fastcall op_reverse(unsigned __int8 *b, unsigned __int64 n)
{
  unsigned __int8 t; // [rsp+0h] [rbp-18h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  for ( i = 0; i < n / 2; ++i )
  {
    t = b[i];
    b[i] = b[n - 1 - i];
    b[n - 1 - i] = t;
  }
}
