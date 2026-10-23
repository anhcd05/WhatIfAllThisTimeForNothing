unsigned __int64 __fastcall b64_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  __int64 v3; // r10
  unsigned __int64 result; // rax
  const unsigned __int8 *v7; // r11
  __int64 v8; // rbx
  __int64 v9; // rcx
  __int64 v10; // rdx
  unsigned __int64 v11; // rdx
  __int64 v12; // r9
  __int64 v13; // rdx
  unsigned __int64 v14; // rdx

  v3 = 0;
  result = 0;
  if ( n > 2 )
  {
    v7 = in + 1;
    v8 = 1LL - (_QWORD)in;
    do
    {
      v9 = *v7;
      v3 += 3;
      v10 = *(v7 - 1);
      v7 += 3;
      v11 = *(v7 - 2) | ((v9 | (v10 << 8)) << 8);
      out[result] = T[v11 >> 18];
      out[result + 1] = T[(v11 >> 12) & 0x3F];
      out[result + 2] = T[(v11 >> 6) & 0x3F];
      out[result + 3] = T[v11 & 0x3F];
      result += 4LL;
    }
    while ( (unsigned __int64)&v7[v8] < n );
  }
  v12 = n - v3;
  if ( v12 == 1 )
  {
    v13 = (16 * in[v3]) & 0x3F;
    out[result] = T[(unsigned __int64)in[v3] << 16 >> 18];
    out[result + 1] = T[v13];
    *(_WORD *)&out[result + 2] = 15677;
    result += 4LL;
    out[result] = 0;
  }
  else
  {
    if ( v12 == 2 )
    {
      v14 = (in[v3 + 1] | ((unsigned __int64)in[v3] << 8)) << 8;
      out[result] = T[v14 >> 18];
      out[result + 1] = T[(v14 >> 12) & 0x3F];
      out[result + 2] = T[(v14 >> 6) & 0x3F];
      out[result + 3] = 61;
      result += 4LL;
    }
    out[result] = 0;
  }
  return result;
}
