// fnv1a_hash = sub_140002A30 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002A30(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r8
  unsigned int i; // r9d
  int v4; // eax

  v2 = 0;
  for ( i = -2128831035; v2 < a2; i = 16777619 * (i ^ v4) )
  {
    v4 = *(unsigned __int8 *)(v2 + a1);
    ++v2;
  }
  return i;
}
