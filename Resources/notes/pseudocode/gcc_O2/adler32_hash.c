__int64 __fastcall adler32_hash(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rsi
  unsigned int v3; // eax
  unsigned int v4; // edx
  int v5; // ecx

  if ( a2 == 0 )
    return 1;
  v2 = &a1[a2];
  v3 = 0;
  v4 = 1;
  do
  {
    v5 = *a1++;
    v4 = (v5 + v4) % 0xFFF1;
    v3 = (v4 + v3) % 0xFFF1;
  }
  while ( v2 != a1 );
  return v4 | (v3 << 16);
}
