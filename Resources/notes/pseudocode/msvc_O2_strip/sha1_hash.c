// sha1_hash = sub_140004720 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004720(__int64 a1, __int64 a2, _BYTE *a3)
{
  _BYTE *v3; // r14
  __int64 v5; // rsi
  int v7; // r15d
  int v8; // r12d
  int v9; // r13d
  unsigned __int64 v10; // rdx
  int v11; // r14d
  int v12; // eax
  int v13; // ecx
  int v14; // eax
  int v15; // ecx
  int v16; // eax
  int v17; // ecx
  int v18; // eax
  int v19; // ecx
  int v20; // eax
  int v21; // ecx
  int v22; // eax
  int v23; // ecx
  int v24; // eax
  int v25; // ecx
  int v26; // eax
  int v27; // ecx
  int v28; // eax
  int v29; // ecx
  int v30; // eax
  int v31; // ecx
  int v32; // eax
  int v33; // ecx
  int v34; // eax
  int v35; // ecx
  int v36; // eax
  int v37; // ecx
  int v38; // eax
  _DWORD *v39; // rdi
  int v40; // ecx
  __int64 v41; // rsi
  int v42; // eax
  int v43; // edx
  int v44; // edx
  int v45; // ecx
  int v46; // r9d
  int v47; // r9d
  int v48; // r8d
  int v49; // r8d
  int v50; // eax
  int v51; // ebx
  int v52; // edi
  int v53; // r8d
  int v54; // edx
  int v55; // r10d
  __int64 v56; // r9
  int v57; // r11d
  int v58; // eax
  int v59; // ecx
  int v60; // ecx
  unsigned int v61; // esi
  int v63; // [rsp+20h] [rbp-E0h]
  int v64; // [rsp+24h] [rbp-DCh]
  unsigned __int64 v65; // [rsp+28h] [rbp-D8h]
  unsigned __int64 v66; // [rsp+30h] [rbp-D0h]
  _DWORD v68[2]; // [rsp+40h] [rbp-C0h]
  _DWORD v69[78]; // [rsp+48h] [rbp-B8h] BYREF
  _BYTE v70[320]; // [rsp+180h] [rbp+80h] BYREF

  v64 = 271733878;
  v63 = -1009589776;
  v3 = a3;
  v66 = ((a2 + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v5 = 8 * a2;
  v7 = 1732584193;
  v8 = -271733879;
  v9 = -1732584194;
  sub_140007EA0(a1: v70, a2: 0, a3: 320);
  sub_140007A40(a1: v70, a2: a1, a3: a2);
  v10 = 0;
  v70[a2] = 0x80;
  v65 = 0;
  *((_BYTE *)&v69[77] + v66 + 3) = v5;
  *((_BYTE *)&v69[77] + v66 + 2) = BYTE1(v5);
  *((_BYTE *)&v69[77] + v66 + 1) = BYTE2(v5);
  *((_BYTE *)&v69[77] + v66) = BYTE3(v5);
  *((_BYTE *)&v69[76] + v66 + 3) = BYTE4(v5);
  *((_BYTE *)&v69[76] + v66 + 2) = BYTE5(v5);
  *((_BYTE *)&v69[76] + v66 + 1) = BYTE6(v5);
  *((_BYTE *)&v69[76] + v66) = HIBYTE(v5);
  if ( v66 == 0 )
  {
    v61 = -1009589776;
    goto LABEL_18;
  }
  v11 = 271733878;
  do
  {
    v12 = (unsigned __int8)v70[v10 + 5];
    v68[0] = (unsigned __int8)v70[v10 + 3]
           | (((unsigned __int8)v70[v10 + 2] | (((unsigned __int8)v70[v10 + 1] | ((unsigned __int8)v70[v10] << 8)) << 8)) << 8);
    v13 = (unsigned __int8)v70[v10 + 7]
        | (((unsigned __int8)v70[v10 + 6] | ((v12 | ((unsigned __int8)v70[v10 + 4] << 8)) << 8)) << 8);
    v14 = (unsigned __int8)v70[v10 + 9];
    v68[1] = v13;
    v15 = (unsigned __int8)v70[v10 + 11]
        | (((unsigned __int8)v70[v10 + 10] | ((v14 | ((unsigned __int8)v70[v10 + 8] << 8)) << 8)) << 8);
    v16 = (unsigned __int8)v70[v10 + 13];
    v69[0] = v15;
    v17 = (unsigned __int8)v70[v10 + 15]
        | (((unsigned __int8)v70[v10 + 14] | ((v16 | ((unsigned __int8)v70[v10 + 12] << 8)) << 8)) << 8);
    v18 = (unsigned __int8)v70[v10 + 17];
    v69[1] = v17;
    v19 = (unsigned __int8)v70[v10 + 19]
        | (((unsigned __int8)v70[v10 + 18] | ((v18 | ((unsigned __int8)v70[v10 + 16] << 8)) << 8)) << 8);
    v20 = (unsigned __int8)v70[v10 + 21];
    v69[2] = v19;
    v21 = (unsigned __int8)v70[v10 + 23]
        | (((unsigned __int8)v70[v10 + 22] | ((v20 | ((unsigned __int8)v70[v10 + 20] << 8)) << 8)) << 8);
    v22 = (unsigned __int8)v70[v10 + 25];
    v69[3] = v21;
    v23 = (unsigned __int8)v70[v10 + 27]
        | (((unsigned __int8)v70[v10 + 26] | ((v22 | ((unsigned __int8)v70[v10 + 24] << 8)) << 8)) << 8);
    v24 = (unsigned __int8)v70[v10 + 29];
    v69[4] = v23;
    v25 = (unsigned __int8)v70[v10 + 31]
        | (((unsigned __int8)v70[v10 + 30] | ((v24 | ((unsigned __int8)v70[v10 + 28] << 8)) << 8)) << 8);
    v26 = (unsigned __int8)v70[v10 + 33];
    v69[5] = v25;
    v27 = (unsigned __int8)v70[v10 + 35]
        | (((unsigned __int8)v70[v10 + 34] | ((v26 | ((unsigned __int8)v70[v10 + 32] << 8)) << 8)) << 8);
    v28 = (unsigned __int8)v70[v10 + 37];
    v69[6] = v27;
    v29 = (unsigned __int8)v70[v10 + 39]
        | (((unsigned __int8)v70[v10 + 38] | ((v28 | ((unsigned __int8)v70[v10 + 36] << 8)) << 8)) << 8);
    v30 = (unsigned __int8)v70[v10 + 41];
    v69[7] = v29;
    v31 = (unsigned __int8)v70[v10 + 43]
        | (((unsigned __int8)v70[v10 + 42] | ((v30 | ((unsigned __int8)v70[v10 + 40] << 8)) << 8)) << 8);
    v32 = (unsigned __int8)v70[v10 + 45];
    v69[8] = v31;
    v33 = (unsigned __int8)v70[v10 + 47]
        | (((unsigned __int8)v70[v10 + 46] | ((v32 | ((unsigned __int8)v70[v10 + 44] << 8)) << 8)) << 8);
    v34 = (unsigned __int8)v70[v10 + 49];
    v69[9] = v33;
    v35 = (unsigned __int8)v70[v10 + 51]
        | (((unsigned __int8)v70[v10 + 50] | ((v34 | ((unsigned __int8)v70[v10 + 48] << 8)) << 8)) << 8);
    v36 = (unsigned __int8)v70[v10 + 53];
    v69[10] = v35;
    v37 = (unsigned __int8)v70[v10 + 55]
        | (((unsigned __int8)v70[v10 + 54] | ((v36 | ((unsigned __int8)v70[v10 + 52] << 8)) << 8)) << 8);
    v38 = (unsigned __int8)v70[v10 + 57];
    v69[11] = v37;
    v39 = v69;
    v40 = (unsigned __int8)v70[v10 + 59]
        | (((unsigned __int8)v70[v10 + 58] | ((v38 | ((unsigned __int8)v70[v10 + 56] << 8)) << 8)) << 8);
    v41 = 8;
    v42 = (unsigned __int8)v70[v10 + 61];
    v69[12] = v40;
    v69[13] = (unsigned __int8)v70[v10 + 63]
            | (((unsigned __int8)v70[v10 + 62] | ((v42 | ((unsigned __int8)v70[v10 + 60] << 8)) << 8)) << 8);
    do
    {
      v43 = *v39 ^ v39[6] ^ v39[11] ^ *(v39 - 2);
      v39 += 8;
      v44 = __ROL4__(v43, 1);
      v39[6] = v44;
      v45 = __ROL4__(*(v39 - 1) ^ *(v39 - 7) ^ v39[4] ^ *(v39 - 9), 1);
      v39[7] = v45;
      v46 = __ROL4__(*(v39 - 6) ^ v39[5] ^ *(v39 - 8) ^ *v39, 1);
      v39[8] = v46;
      v47 = v39[3] ^ v46;
      v48 = __ROL4__(*(v39 - 5) ^ *(v39 - 7) ^ v44 ^ v39[1], 1);
      v39[9] = v48;
      v49 = *(v39 - 2) ^ v48;
      v50 = __ROL4__(*(v39 - 6) ^ *(v39 - 4) ^ v45 ^ v39[2], 1);
      v39[10] = v50;
      v39[11] = __ROL4__(*(v39 - 5) ^ *(v39 - 3) ^ v47, 1);
      v39[12] = __ROL4__(v39[4] ^ *(v39 - 4) ^ v49, 1);
      v39[13] = __ROL4__(v39[5] ^ *(v39 - 1) ^ *(v39 - 3) ^ v50, 1);
      --v41;
    }
    while ( v41 != 0 );
    v51 = v7;
    v52 = v63;
    v53 = v8;
    v54 = v9;
    v55 = v11;
    v56 = 0;
    do
    {
      if ( v56 < 20 )
      {
        v57 = 1518500249;
        v58 = v53 & v54 | v55 & ~v53;
        goto LABEL_14;
      }
      if ( v56 >= 40 )
      {
        if ( v56 < 60 )
        {
          v57 = -1894007588;
          v58 = v53 & v54 | v55 & (v53 | v54);
          goto LABEL_14;
        }
        v57 = -899497514;
      }
      else
      {
        v57 = 1859775393;
      }
      v58 = v53 ^ v54 ^ v55;
LABEL_14:
      v59 = v68[v56++] + __ROL4__(v51, 5);
      v60 = v52 + v58 + v57 + v59;
      v52 = v55;
      v55 = v54;
      v54 = __ROR4__(v53, 2);
      v53 = v51;
      v51 = v60;
    }
    while ( v56 < 80 );
    v9 += v54;
    v61 = v52 + v63;
    v7 += v60;
    v10 = v65 + 64;
    v63 += v52;
    v8 += v53;
    v65 = v10;
    v11 += v55;
  }
  while ( v10 < v66 );
  v64 = v11;
  v3 = a3;
LABEL_18:
  *v3 = HIBYTE(v7);
  v3[1] = BYTE2(v7);
  v3[2] = BYTE1(v7);
  v3[4] = HIBYTE(v8);
  v3[5] = BYTE2(v8);
  v3[6] = BYTE1(v8);
  v3[8] = HIBYTE(v9);
  v3[9] = BYTE2(v9);
  v3[10] = BYTE1(v9);
  v3[12] = HIBYTE(v64);
  v3[13] = BYTE2(v64);
  v3[14] = BYTE1(v64);
  v3[16] = HIBYTE(v61);
  v3[17] = BYTE2(v61);
  v3[18] = BYTE1(v61);
  v3[3] = v7;
  v3[7] = v8;
  v3[11] = v9;
  v3[15] = v64;
  v3[19] = v61;
  return v61 >> 8;
}
