// md5_hash = sub_1400039C0 (bản strip, IDA không có tên hàm)
int *__fastcall sub_1400039C0(__int64 a1, __int64 a2, int *a3)
{
  unsigned __int64 v5; // r14
  int v6; // r15d
  int v7; // esi
  int v8; // r12d
  int v9; // r13d
  unsigned __int64 v10; // rbp
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
  int v40; // [rsp+20h] [rbp-1E8h]
  int v41; // [rsp+24h] [rbp-1E4h]
  unsigned __int64 v42; // [rsp+28h] [rbp-1E0h]
  _QWORD v44[6]; // [rsp+40h] [rbp-1C8h]
  _QWORD v45[2]; // [rsp+70h] [rbp-198h]
  _QWORD v46[40]; // [rsp+80h] [rbp-188h] BYREF

  v5 = ((a2 + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v6 = 1732584193;
  v7 = 271733878;
  v42 = v5;
  v40 = 1732584193;
  v41 = 271733878;
  v8 = -271733879;
  v9 = -1732584194;
  sub_140007EA0(a1: v46, a2: 0, a3: 320);
  sub_140007A40(a1: v46, a2: a1, a3: a2);
  v10 = 0;
  *((_BYTE *)v46 + a2) = 0x80;
  *(_QWORD *)((char *)&v45[1] + v5) = 8 * a2;
  if ( v5 != 0 )
  {
    do
    {
      v11 = 0;
      v12 = v6;
      v13 = *(_OWORD *)&v46[v10 / 8 + 2];
      v14 = v8;
      *(_OWORD *)v44 = *(_OWORD *)&v46[v10 / 8];
      v15 = v9;
      v16 = *(_OWORD *)&v46[v10 / 8 + 4];
      v17 = v7;
      v18 = 0;
      *(_OWORD *)&v44[2] = v13;
      v19 = *(_OWORD *)&v46[v10 / 8 + 6];
      *(_OWORD *)&v44[4] = v16;
      *(_OWORD *)v45 = v19;
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
        v25 = __ROL4__(
                v12 + dword_1400184D0[v18 + 256] + *((_DWORD *)v44 + v21) + v20,
                *(_DWORD *)&asc_140018ED0[v18 * 4])
            + v14;
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
        v30 = __ROL4__(
                v17 + dword_1400184D0[v18 + 257] + *((_DWORD *)v44 + v28) + v27,
                *(_DWORD *)((char *)&unk_140018ED4 + v18 * 4))
            + v25;
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
        v35 = __ROL4__(
                v15 + dword_1400184D0[v18 + 258] + *((_DWORD *)v44 + v32) + v31,
                *(_DWORD *)((char *)&unk_140018ED8 + v18 * 4))
            + v30;
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
        v38 = __ROL4__(
                v24 + dword_1400184D0[v18 + 259] + *((_DWORD *)v44 + v34) + v36,
                *(_DWORD *)((char *)&unk_140018EDC + v18 * 4));
        v18 += 4;
        v14 = v38 + v35;
      }
      while ( v11 < 64 );
      v8 += v14;
      v6 = v12 + v40;
      v7 = v17 + v41;
      v40 += v12;
      v9 += v15;
      v41 += v17;
      v10 += 64LL;
    }
    while ( v10 < v42 );
  }
  *a3 = v6;
  a3[1] = v8;
  a3[2] = v9;
  a3[3] = v7;
  return a3;
}
