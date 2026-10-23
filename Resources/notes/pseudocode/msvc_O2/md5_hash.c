void __fastcall md5_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  size_t v5; // r14
  int v6; // r15d
  int v7; // esi
  int v8; // r12d
  int v9; // r13d
  size_t v10; // rbp
  int v11; // r8d
  int v12; // r11d
  __int128 v13; // xmm1
  int v14; // r9d
  int v15; // ebx
  __int128 v16; // xmm0
  int v17; // r10d
  __int64 v18; // r14
  __int128 v19; // xmm1
  int v20; // eax
  __int64 v21; // rcx
  char v22; // cl
  int v23; // esi
  int v24; // edi
  int v25; // r9d
  int v26; // eax
  int v27; // edx
  __int64 v28; // rax
  char v29; // al
  int v30; // r9d
  int v31; // edx
  __int64 v32; // rax
  char v33; // al
  __int64 v34; // rcx
  int v35; // r9d
  int v36; // edx
  char v37; // cl
  int v38; // edx
  int v39; // [rsp+20h] [rbp-1E8h]
  int v40; // [rsp+24h] [rbp-1E4h]
  size_t v41; // [rsp+28h] [rbp-1E0h]
  unsigned int M[16]; // [rsp+40h] [rbp-1C8h]
  unsigned __int8 buf[320]; // [rsp+80h] [rbp-188h] BYREF

  v5 = ((n + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v6 = 1732584193;
  v7 = 271733878;
  v41 = v5;
  v39 = 1732584193;
  v40 = 271733878;
  v8 = -271733879;
  v9 = -1732584194;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  v10 = 0;
  buf[n] = 0x80;
  *(_QWORD *)((char *)&M[14] + v5) = 8 * n;
  if ( v5 != 0 )
  {
    do
    {
      v11 = 0;
      v12 = v6;
      v13 = *(_OWORD *)&buf[v10 + 16];
      v14 = v8;
      *(_OWORD *)M = *(_OWORD *)&buf[v10];
      v15 = v9;
      v16 = *(_OWORD *)&buf[v10 + 32];
      v17 = v7;
      v18 = 0;
      *(_OWORD *)&M[4] = v13;
      v19 = *(_OWORD *)&buf[v10 + 48];
      *(_OWORD *)&M[8] = v16;
      *(_OWORD *)&M[12] = v19;
      do
      {
        if ( v11 >= 16 )
        {
          if ( v11 >= 32 )
          {
            if ( v11 >= 48 )
            {
              v20 = v15 ^ (v14 | ~v17);
              v22 = 7 * v11;
            }
            else
            {
              v20 = v14 ^ v15 ^ v17;
              v22 = v11 + 2 * v11 + 5;
            }
          }
          else
          {
            v20 = v14 & v17 | v15 & ~v17;
            v22 = v11 + 4 * v11 + 1;
          }
          v21 = v22 & 0xF;
        }
        else
        {
          v20 = v14 & v15 | v17 & ~v14;
          v21 = (unsigned int)v11;
        }
        v23 = v11 + 2;
        v24 = v14;
        v25 = __ROL4__(v12 + MD5_K[v18] + M[v21] + v20, R[v18]) + v14;
        v26 = v11 + 1;
        if ( v11 + 1 >= 16 )
        {
          if ( v26 >= 32 )
          {
            if ( v26 >= 48 )
            {
              v27 = v24 ^ (v25 | ~v15);
              v29 = 7 * (v11 + 1);
            }
            else
            {
              v27 = v25 ^ v24 ^ v15;
              v29 = v11 + 2 * (v11 - 4);
            }
          }
          else
          {
            v27 = v25 & v15 | v24 & ~v15;
            v29 = v11 + 4 * v11 + 6;
          }
          v28 = v29 & 0xF;
        }
        else
        {
          v27 = v25 & v24 | v15 & ~v25;
          v28 = (unsigned int)(v11 + 1);
        }
        v12 = v25;
        v30 = __ROL4__(v17 + MD5_K[v18 + 1] + M[v28] + v27, R[v18 + 1]) + v25;
        if ( v23 >= 16 )
        {
          if ( v23 >= 32 )
          {
            if ( v23 >= 48 )
            {
              v31 = v12 ^ (v30 | ~v24);
              v33 = 7 * v11 - 2;
            }
            else
            {
              v31 = v30 ^ v12 ^ v24;
              v33 = v11 + 2 * v11 - 5;
            }
          }
          else
          {
            v31 = v30 & v24 | v12 & ~v24;
            v33 = 5 * (v11 - 1);
          }
          v32 = v33 & 0xF;
        }
        else
        {
          v31 = v30 & v12 | v24 & ~v30;
          v32 = (unsigned int)v23;
        }
        v17 = v30;
        v34 = (unsigned int)(v11 + 3);
        v35 = __ROL4__(v15 + MD5_K[v18 + 2] + M[v32] + v31, R[v18 + 2]) + v30;
        if ( (int)v34 >= 16 )
        {
          if ( (int)v34 >= 32 )
          {
            if ( (int)v34 >= 48 )
            {
              v36 = v17 ^ (v35 | ~v12);
              v37 = 7 * v11 + 5;
            }
            else
            {
              v36 = v35 ^ v17 ^ v12;
              v37 = v11 + 2 * (v11 - 1);
            }
          }
          else
          {
            v37 = 5 * v11;
            v36 = v35 & v12 | v17 & ~v12;
          }
          v34 = v37 & 0xF;
        }
        else
        {
          v36 = v35 & v17 | v12 & ~v35;
        }
        v15 = v35;
        v11 += 4;
        v38 = __ROL4__(v24 + MD5_K[v18 + 3] + M[v34] + v36, R[v18 + 3]);
        v18 += 4;
        v14 = v38 + v35;
      }
      while ( v11 < 64 );
      v8 += v14;
      v6 = v12 + v39;
      v7 = v17 + v40;
      v39 += v12;
      v9 += v15;
      v40 += v17;
      v10 += 64LL;
    }
    while ( v10 < v41 );
  }
  *(_DWORD *)out = v6;
  *((_DWORD *)out + 1) = v8;
  *((_DWORD *)out + 2) = v9;
  *((_DWORD *)out + 3) = v7;
}
