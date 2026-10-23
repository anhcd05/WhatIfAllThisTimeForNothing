__int64 __fastcall xor_repeat(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 i; // r10
  __int64 result; // rax

  if ( a2 != 0 )
  {
    for ( i = 0; i != a2; ++i )
    {
      result = *(unsigned __int8 *)(a3 + i % a4);
      *(_BYTE *)(a1 + i) ^= result;
    }
  }
  return result;
}
