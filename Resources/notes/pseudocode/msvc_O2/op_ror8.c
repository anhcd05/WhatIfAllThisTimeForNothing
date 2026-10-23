void __fastcall op_ror8(char *b, unsigned __int64 n, char k)
{
  char v4; // r9

  for ( ; n != 0; --n )
  {
    v4 = *b++;
    *(b - 1) = __ROR1__(v4, k);
  }
}
