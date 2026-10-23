// djb2_hash = sub_140002A00 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002A00(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r8
  __int64 result; // rax
  int v4; // r9d

  v2 = 0;
  for ( result = 5381; v2 < a2; result = (unsigned int)(v4 + 33 * result) )
  {
    v4 = *(unsigned __int8 *)(v2 + a1);
    ++v2;
  }
  return result;
}
