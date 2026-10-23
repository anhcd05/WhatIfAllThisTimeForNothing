// fnv1a_hash = sub_140004C30 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004C30(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rdx
  __int64 result; // rax
  int v4; // r8d

  if ( a2 == 0 )
    return 2166136261LL;
  v2 = &a1[a2];
  LODWORD(result) = -2128831035;
  do
  {
    v4 = *a1++;
    result = 16777619 * (v4 ^ (unsigned int)result);
  }
  while ( v2 != a1 );
  return result;
}
