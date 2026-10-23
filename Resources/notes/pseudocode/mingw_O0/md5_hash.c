__int64 __fastcall md5_hash(const void *a1, size_t a2, int *a3)
{
  __int64 result; // rax
  _DWORD v4[18]; // [rsp+20h] [rbp-60h] BYREF
  size_t v5; // [rsp+68h] [rbp-18h]
  unsigned int v6; // [rsp+70h] [rbp-10h]
  int v7; // [rsp+74h] [rbp-Ch]
  int v8; // [rsp+78h] [rbp-8h]
  int v9; // [rsp+7Ch] [rbp-4h]
  _BYTE v10[320]; // [rsp+80h] [rbp+0h] BYREF
  size_t v11; // [rsp+1C0h] [rbp+140h]
  int v12; // [rsp+1CCh] [rbp+14Ch]
  int v13; // [rsp+1D0h] [rbp+150h]
  int j; // [rsp+1D4h] [rbp+154h]
  unsigned int v15; // [rsp+1D8h] [rbp+158h]
  int v16; // [rsp+1DCh] [rbp+15Ch]
  int v17; // [rsp+1E0h] [rbp+160h]
  int v18; // [rsp+1E4h] [rbp+164h]
  size_t i; // [rsp+1E8h] [rbp+168h]

  v9 = 1732584193;
  v8 = -271733879;
  v7 = -1732584194;
  v6 = 271733878;
  v11 = (((a2 + 8) >> 6) + 1) << 6;
  v5 = 8 * a2;
  memset(a1: v10, Val: 0, Size: sizeof(v10));
  memcpy_0(a1: v10, Src: a1, Size: a2);
  v10[a2] = 0x80;
  *(_QWORD *)&v10[v11 - 8] = v5;
  for ( i = 0; i < v11; i += 64LL )
  {
    v18 = v9;
    v17 = v8;
    v16 = v7;
    v15 = v6;
    memcpy_0(a1: v4, Src: &v10[i], Size: 0x40u);
    for ( j = 0; j <= 63; ++j )
    {
      if ( j > 15 )
      {
        if ( j > 31 )
        {
          if ( j > 47 )
          {
            v13 = v16 ^ (v17 | ~v15);
            v12 = (7 * (_BYTE)j) & 0xF;
          }
          else
          {
            v13 = v15 ^ v16 ^ v17;
            v12 = (3 * (_BYTE)j + 5) & 0xF;
          }
        }
        else
        {
          v13 = v17 & v15 | v16 & ~v15;
          v12 = (5 * (_BYTE)j + 1) & 0xF;
        }
      }
      else
      {
        v13 = v16 & v17 | v15 & ~v17;
        v12 = j;
      }
      v13 += v18 + MD5_K[j] + v4[v12];
      v18 = v15;
      v15 = v16;
      v16 = v17;
      v17 += __ROL4__(v13, *(_DWORD *)&R_1[4 * j]);
    }
    v9 += v18;
    v8 += v17;
    v7 += v16;
    v6 += v15;
  }
  *a3 = v9;
  a3[1] = v8;
  a3[2] = v7;
  result = v6;
  a3[3] = v6;
  return result;
}
