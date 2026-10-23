__int64 __fastcall tea_encrypt(unsigned int *a1, int *a2)
{
  unsigned int v3; // ecx
  unsigned int v4; // edx
  int v5; // r11d
  int v6; // r9d
  int v7; // r8d
  int v8; // edi
  int v9; // esi
  __int64 result; // rax

  v3 = *a1;
  v4 = a1[1];
  v5 = *a2;
  v6 = a2[1];
  v7 = a2[2];
  v8 = a2[3];
  v9 = 0;
  do
  {
    v9 -= 1640531527;
    v3 += (v9 + v4) ^ (v6 + (v4 >> 5)) ^ (v5 + 16 * v4);
    result = (v9 + v3) ^ (v8 + (v3 >> 5)) ^ (v7 + 16 * v3);
    v4 += result;
  }
  while ( v9 != -957401312 );
  *a1 = v3;
  a1[1] = v4;
  return result;
}
