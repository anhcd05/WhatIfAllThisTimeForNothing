__int64 __fastcall djb2_hash(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+0h] [rbp-10h]
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  v4 = 5381;
  for ( i = 0; i < a2; ++i )
    v4 = 33 * v4 + *(unsigned __int8 *)(a1 + i);
  return v4;
}
