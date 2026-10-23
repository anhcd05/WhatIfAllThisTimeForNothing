__int64 __fastcall xtea_decrypt(unsigned int *a1, __int64 a2)
{
  __int64 result; // rax
  unsigned int v3; // r8d
  unsigned int v5; // ecx
  int v6; // r9d

  LODWORD(result) = -957401312;
  v3 = *a1;
  v5 = a1[1];
  do
  {
    v6 = result + *(_DWORD *)(a2 + 4LL * (((unsigned int)result >> 11) & 3));
    result = (unsigned int)(result + 1640531527);
    v5 -= v6 ^ (v3 + ((v3 >> 5) ^ (16 * v3)));
    v3 -= (result + *(_DWORD *)(a2 + 4 * (result & 3))) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));
  }
  while ( (_DWORD)result != 0 );
  *a1 = v3;
  a1[1] = v5;
  return result;
}
