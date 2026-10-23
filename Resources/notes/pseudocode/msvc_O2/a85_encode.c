__int64 __fastcall a85_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  __int64 v3; // rdi
  unsigned __int64 v6; // rsi
  const unsigned __int8 *v7; // rbx
  __int64 v8; // r14
  unsigned int v9; // ecx
  __int64 v10; // rax
  unsigned int v11; // r10d
  __int64 v12; // rbp
  unsigned int v13; // r9d
  unsigned int v14; // r8d
  unsigned int v15; // r9d
  __int64 result; // rax
  unsigned __int8 b[4]; // [rsp+20h] [rbp-48h] BYREF
  char v18; // [rsp+24h] [rbp-44h]

  v3 = 0;
  v6 = 0;
  if ( n >= 4 )
  {
    v7 = in + 1;
    v8 = 3LL - (_QWORD)in;
    do
    {
      v9 = v7[2] | ((v7[1] | ((*v7 | (*(v7 - 1) << 8)) << 8)) << 8);
      if ( v9 != 0 )
      {
        v11 = v9 / 0x55 / 0x55;
        b[3] = v9 / 0x55 % 0x55 + 33;
        b[2] = v11 % 0x55 + 33;
        b[1] = v11 / 0x55 % 0x55 + 33;
        b[0] = v11 / 0x55 / 0x55 % 0x55 + 33;
        *(_DWORD *)&out[v3] = *(_DWORD *)b;
        v10 = 5;
        out[v3 + 4] = v9 % 0x55 + 33;
      }
      else
      {
        out[v3] = 122;
        v10 = 1;
      }
      v7 += 4;
      v3 += v10;
      v6 += 4LL;
    }
    while ( (unsigned __int64)&v7[v8] <= n );
  }
  if ( v6 >= n )
  {
    out[v3] = 0;
    return v3;
  }
  else
  {
    v12 = n - v6;
    *(_DWORD *)b = 0;
    memmove(a1: b, Src: &in[v6], Size: n - v6);
    v13 = b[3] | ((b[2] | ((b[1] | (b[0] << 8)) << 8)) << 8);
    v14 = v13 / 0x55;
    v18 = v13 % 0x55 + 33;
    v15 = v13 / 0x55 / 0x55;
    b[3] = v14 - 85 * v15 + 33;
    b[2] = v15 % 0x55 + 33;
    b[1] = v15 / 0x55 % 0x55 + 33;
    b[0] = v15 / 0x55 / 0x55 % 0x55 + 33;
    memmove(a1: &out[v3], Src: b, Size: v12 + 1);
    result = v3 + v12 + 1;
    out[result] = 0;
  }
  return result;
}
