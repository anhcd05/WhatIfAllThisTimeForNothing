__int64 __fastcall fnv1a_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned __int64 v2; // r8
  unsigned int i; // r9d
  int v4; // eax

  v2 = 0;
  for ( i = -2128831035; v2 < n; i = 16777619 * (i ^ v4) )
    v4 = p[v2++];
  return i;
}
