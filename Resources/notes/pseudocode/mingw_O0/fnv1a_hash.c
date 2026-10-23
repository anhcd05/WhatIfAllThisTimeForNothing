__int64 __fastcall fnv1a_hash(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+0h] [rbp-10h]
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  v4 = -2128831035;
  for ( i = 0; i < a2; ++i )
    v4 = 16777619 * (*(unsigned __int8 *)(a1 + i) ^ v4);
  return v4;
}
