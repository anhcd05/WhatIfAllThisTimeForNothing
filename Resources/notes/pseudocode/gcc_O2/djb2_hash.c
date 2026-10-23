__int64 __fastcall djb2_hash(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rsi
  __int64 result; // rax

  if ( a2 == 0 )
    return 5381;
  v2 = &a1[a2];
  LODWORD(result) = 5381;
  do
    result = (unsigned int)*a1++ + 33 * (_DWORD)result;
  while ( a1 != v2 );
  return result;
}
