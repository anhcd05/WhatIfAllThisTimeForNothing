__int64 __fastcall adler32_hash(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+10h] [rbp-10h]
  unsigned int v4; // [rsp+18h] [rbp-8h]
  unsigned int v5; // [rsp+1Ch] [rbp-4h]

  v5 = 1;
  v4 = 0;
  for ( i = 0; i < a2; ++i )
  {
    v5 = (v5 + *(unsigned __int8 *)(a1 + i)) % 0xFFF1;
    v4 = (v5 + v4) % 0xFFF1;
  }
  return v5 | (v4 << 16);
}
