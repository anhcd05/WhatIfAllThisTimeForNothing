__int64 __fastcall adler32_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int a; // [rsp+0h] [rbp-18h]
  unsigned int b; // [rsp+4h] [rbp-14h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  a = 1;
  b = 0;
  for ( i = 0; i < n; ++i )
  {
    a = (p[i] + a) % 0xFFF1;
    b = (a + b) % 0xFFF1;
  }
  return a | (b << 16);
}
