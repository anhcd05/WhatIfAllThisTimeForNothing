void __fastcall mix_chain(unsigned __int8 *b, unsigned __int64 n)
{
  unsigned __int64 v2; // rax
  char i; // r9
  unsigned __int8 v4; // r8

  v2 = 0;
  for ( i = 66; v2 < n; ++v2 )
  {
    v4 = i ^ (__ROL1__(b[v2] ^ (v2 + 90), 3) + 19);
    b[v2] = v4;
    i = v4;
  }
}
