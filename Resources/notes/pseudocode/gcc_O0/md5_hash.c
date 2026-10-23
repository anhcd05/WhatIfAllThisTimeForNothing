__int64 __fastcall md5_hash(const void *a1, size_t a2, int *a3)
{
  __int64 result; // rax
  _DWORD dest[18]; // [rsp+20h] [rbp-1D0h] BYREF
  size_t v8; // [rsp+68h] [rbp-188h]
  unsigned int v9; // [rsp+70h] [rbp-180h]
  int v10; // [rsp+74h] [rbp-17Ch]
  int v11; // [rsp+78h] [rbp-178h]
  int v12; // [rsp+7Ch] [rbp-174h]
  _BYTE s[320]; // [rsp+80h] [rbp-170h] BYREF
  size_t v14; // [rsp+1C0h] [rbp-30h]
  int v15; // [rsp+1CCh] [rbp-24h]
  int v16; // [rsp+1D0h] [rbp-20h]
  int j; // [rsp+1D4h] [rbp-1Ch]
  unsigned int v18; // [rsp+1D8h] [rbp-18h]
  int v19; // [rsp+1DCh] [rbp-14h]
  int v20; // [rsp+1E0h] [rbp-10h]
  int v21; // [rsp+1E4h] [rbp-Ch]
  size_t i; // [rsp+1E8h] [rbp-8h]

  v12 = 1732584193;
  v11 = -271733879;
  v10 = -1732584194;
  v9 = 271733878;
  v14 = (((a2 + 8) >> 6) + 1) << 6;
  v8 = 8 * a2;
  memset(s, c: 0, n: sizeof(s));
  memcpy(dest: s, src: a1, n: a2);
  s[a2] = 0x80;
  *(_QWORD *)&s[v14 - 8] = v8;
  for ( i = 0; i < v14; i += 64LL )
  {
    v21 = v12;
    v20 = v11;
    v19 = v10;
    v18 = v9;
    memcpy(dest, src: &s[i], n: 0x40u);
    for ( j = 0; j <= 63; ++j )
    {
      if ( j > 15 )
      {
        if ( j > 31 )
        {
          if ( j > 47 )
          {
            v16 = v19 ^ (v20 | ~v18);
            v15 = (7 * (_BYTE)j) & 0xF;
          }
          else
          {
            v16 = v18 ^ v19 ^ v20;
            v15 = (3 * (_BYTE)j + 5) & 0xF;
          }
        }
        else
        {
          v16 = v20 & v18 | v19 & ~v18;
          v15 = (5 * (_BYTE)j + 1) & 0xF;
        }
      }
      else
      {
        v16 = v19 & v20 | v18 & ~v20;
        v15 = j;
      }
      v16 += v21 + MD5_K[j] + dest[v15];
      v21 = v18;
      v18 = v19;
      v19 = v20;
      v20 += __ROL4__(v16, *(_DWORD *)&R_1[4 * j]);
    }
    v12 += v21;
    v11 += v20;
    v10 += v19;
    v9 += v18;
  }
  *a3 = v12;
  a3[1] = v11;
  a3[2] = v10;
  result = v9;
  a3[3] = v9;
  return result;
}
