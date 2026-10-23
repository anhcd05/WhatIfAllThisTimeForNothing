__int64 __fastcall djb2_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned __int64 v2; // r8
  __int64 result; // rax
  int v4; // r9d

  v2 = 0;
  for ( result = 5381; v2 < n; result = (unsigned int)(v4 + 33 * result) )
    v4 = p[v2++];
  return result;
}
