// xtea_encrypt = sub_2FD0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2FD0(unsigned int *a1, __int64 a2)
{
  unsigned int v3; // ecx
  unsigned int v4; // esi
  __int64 result; // rax
  int v7; // edi

  v3 = a1[1];
  v4 = *a1;
  LODWORD(result) = 0;
  do
  {
    v7 = result + *(_DWORD *)(a2 + 4 * (result & 3));
    result = (unsigned int)(result - 1640531527);
    v4 += v7 ^ (v3 + ((v3 >> 5) ^ (16 * v3)));
    v3 += (result + *(_DWORD *)(a2 + 4LL * (((unsigned int)result >> 11) & 3))) ^ (v4 + ((v4 >> 5) ^ (16 * v4)));
  }
  while ( (_DWORD)result != -957401312 );
  *a1 = v4;
  a1[1] = v3;
  return result;
}
