__int64 __fastcall adler32_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int v2; // r8d
  unsigned int v3; // r9d
  unsigned __int64 i; // r10
  int v5; // eax

  v2 = 0;
  v3 = 1;
  for ( i = 0; i < n; v2 = (v2 + v3) % 0xFFF1 )
  {
    v5 = p[i++];
    v3 = (v5 + v3) % 0xFFF1;
  }
  return v3 | (v2 << 16);
}
