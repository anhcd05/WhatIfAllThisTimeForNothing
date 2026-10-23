// sha256_hash = sub_140004DD0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004DD0(__int64 a1, __int64 a2, _BYTE *a3)
{
  __int64 v3; // rsi
  _BYTE *v4; // r13
  int v7; // r14d
  int v8; // r15d
  int v9; // r12d
  unsigned __int64 v10; // rdi
  int v11; // r13d
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
  int v39; // ecx
  int v40; // eax
  int v41; // ecx
  int v42; // eax
  __int64 v43; // rdi
  int v44; // ecx
  _DWORD *v45; // rax
  unsigned int v46; // r11d
  unsigned int v47; // ebx
  unsigned int v48; // r10d
  unsigned int v49; // r11d
  unsigned int v50; // r9d
  unsigned int v51; // r11d
  unsigned int v52; // edx
  int v53; // r10d
  int v54; // r9d
  int v55; // esi
  int v56; // r14d
  int v57; // ebx
  int v58; // r15d
  int v59; // edi
  int v60; // r12d
  __int64 v61; // r11
  int v62; // r8d
  int v63; // edx
  int v64; // ecx
  int v65; // r9d
  int v66; // edx
  int v67; // r10d
  int v68; // r8d
  int v69; // r11d
  int v70; // ebx
  int v72; // [rsp+20h] [rbp-E0h]
  int v73; // [rsp+24h] [rbp-DCh]
  int v74; // [rsp+28h] [rbp-D8h]
  int v75; // [rsp+2Ch] [rbp-D4h]
  int v76; // [rsp+30h] [rbp-D0h]
  int v77; // [rsp+34h] [rbp-CCh]
  int v78; // [rsp+38h] [rbp-C8h]
  int v79; // [rsp+3Ch] [rbp-C4h]
  unsigned __int64 v80; // [rsp+40h] [rbp-C0h]
  unsigned __int64 v81; // [rsp+48h] [rbp-B8h]
  char v83; // [rsp+58h] [rbp-A8h]
  char v84; // [rsp+5Ch] [rbp-A4h]
  char v85; // [rsp+60h] [rbp-A0h]
  char v86; // [rsp+64h] [rbp-9Ch]
  char v87; // [rsp+68h] [rbp-98h]
  char v88; // [rsp+6Ch] [rbp-94h]
  char v89; // [rsp+70h] [rbp-90h]
  unsigned __int8 v90; // [rsp+74h] [rbp-8Ch]
  _DWORD v91[64]; // [rsp+80h] [rbp-80h] BYREF
  _BYTE v92[320]; // [rsp+180h] [rbp+80h] BYREF

  v3 = 8 * a2;
  v4 = a3;
  v81 = ((a2 + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v74 = -1521486534;
  v86 = 58;
  v7 = 1779033703;
  v79 = 1779033703;
  v75 = 1359893119;
  v8 = -1150833019;
  v87 = 127;
  v9 = 1013904242;
  v83 = 103;
  v76 = -1694144372;
  v88 = -116;
  v72 = -1150833019;
  v77 = 528734635;
  v89 = -85;
  v78 = 1541459225;
  v90 = 25;
  v84 = -123;
  v73 = 1013904242;
  v85 = 114;
  sub_140007EA0(a1: v92, a2: 0, a3: 320);
  sub_140007A40(a1: v92, a2: a1, a3: a2);
  v92[a2] = 0x80;
  v10 = 0;
  v80 = 0;
  *((_BYTE *)&v91[63] + v81 + 3) = v3;
  *((_BYTE *)&v91[63] + v81 + 2) = BYTE1(v3);
  *((_BYTE *)&v91[63] + v81 + 1) = BYTE2(v3);
  *((_BYTE *)&v91[63] + v81) = BYTE3(v3);
  *((_BYTE *)&v91[62] + v81 + 3) = BYTE4(v3);
  *((_BYTE *)&v91[62] + v81 + 2) = BYTE5(v3);
  *((_BYTE *)&v91[62] + v81 + 1) = BYTE6(v3);
  *((_BYTE *)&v91[62] + v81) = HIBYTE(v3);
  if ( v81 != 0 )
  {
    v11 = 1779033703;
    while ( 1 )
    {
      v12 = (unsigned __int8)v92[v10 + 5];
      v91[0] = (unsigned __int8)v92[v10 + 3]
             | (((unsigned __int8)v92[v10 + 2]
               | (((unsigned __int8)v92[v10 + 1] | ((unsigned __int8)v92[v10] << 8)) << 8)) << 8);
      v13 = (unsigned __int8)v92[v10 + 7]
          | (((unsigned __int8)v92[v10 + 6] | ((v12 | ((unsigned __int8)v92[v10 + 4] << 8)) << 8)) << 8);
      v14 = (unsigned __int8)v92[v10 + 9];
      v91[1] = v13;
      v15 = (unsigned __int8)v92[v10 + 11]
          | (((unsigned __int8)v92[v10 + 10] | ((v14 | ((unsigned __int8)v92[v10 + 8] << 8)) << 8)) << 8);
      v16 = (unsigned __int8)v92[v10 + 12];
      v91[2] = v15;
      v17 = (unsigned __int8)v92[v10 + 15]
          | (((unsigned __int8)v92[v10 + 14] | (((v16 << 8) | (unsigned __int8)v92[v10 + 13]) << 8)) << 8);
      v18 = (unsigned __int8)v92[v10 + 17];
      v91[3] = v17;
      v19 = (unsigned __int8)v92[v10 + 19]
          | (((unsigned __int8)v92[v10 + 18] | ((v18 | ((unsigned __int8)v92[v10 + 16] << 8)) << 8)) << 8);
      v20 = (unsigned __int8)v92[v10 + 21];
      v91[4] = v19;
      v21 = (unsigned __int8)v92[v10 + 23]
          | (((unsigned __int8)v92[v10 + 22] | ((v20 | ((unsigned __int8)v92[v10 + 20] << 8)) << 8)) << 8);
      v22 = (unsigned __int8)v92[v10 + 25];
      v91[5] = v21;
      v23 = (unsigned __int8)v92[v10 + 27]
          | (((unsigned __int8)v92[v10 + 26] | ((v22 | ((unsigned __int8)v92[v10 + 24] << 8)) << 8)) << 8);
      v24 = (unsigned __int8)v92[v10 + 29];
      v91[6] = v23;
      v25 = (unsigned __int8)v92[v10 + 31]
          | (((unsigned __int8)v92[v10 + 30] | ((v24 | ((unsigned __int8)v92[v10 + 28] << 8)) << 8)) << 8);
      v26 = (unsigned __int8)v92[v10 + 33];
      v91[7] = v25;
      v27 = (unsigned __int8)v92[v10 + 35]
          | (((unsigned __int8)v92[v10 + 34] | ((v26 | ((unsigned __int8)v92[v10 + 32] << 8)) << 8)) << 8);
      v28 = (unsigned __int8)v92[v10 + 37];
      v91[8] = v27;
      v29 = (unsigned __int8)v92[v10 + 39]
          | (((unsigned __int8)v92[v10 + 38] | ((v28 | ((unsigned __int8)v92[v10 + 36] << 8)) << 8)) << 8);
      v30 = (unsigned __int8)v92[v10 + 41];
      v91[9] = v29;
      v31 = (unsigned __int8)v92[v10 + 43]
          | (((unsigned __int8)v92[v10 + 42] | ((v30 | ((unsigned __int8)v92[v10 + 40] << 8)) << 8)) << 8);
      v32 = (unsigned __int8)v92[v10 + 45];
      v91[10] = v31;
      v33 = (unsigned __int8)v92[v10 + 47]
          | (((unsigned __int8)v92[v10 + 46] | ((v32 | ((unsigned __int8)v92[v10 + 44] << 8)) << 8)) << 8);
      v34 = (unsigned __int8)v92[v10 + 49];
      v91[11] = v33;
      v35 = (unsigned __int8)v92[v10 + 51]
          | (((unsigned __int8)v92[v10 + 50] | ((v34 | ((unsigned __int8)v92[v10 + 48] << 8)) << 8)) << 8);
      v36 = (unsigned __int8)v92[v10 + 53];
      v91[12] = v35;
      v37 = (unsigned __int8)v92[v10 + 55]
          | (((unsigned __int8)v92[v10 + 54] | ((v36 | ((unsigned __int8)v92[v10 + 52] << 8)) << 8)) << 8);
      v38 = (unsigned __int8)v92[v10 + 57];
      v91[13] = v37;
      v39 = (unsigned __int8)v92[v10 + 59]
          | (((unsigned __int8)v92[v10 + 58] | ((v38 | ((unsigned __int8)v92[v10 + 56] << 8)) << 8)) << 8);
      v40 = (unsigned __int8)v92[v10 + 61];
      v91[14] = v39;
      v41 = (unsigned __int8)v92[v10 + 62] | ((v40 | ((unsigned __int8)v92[v10 + 60] << 8)) << 8);
      v42 = (unsigned __int8)v92[v10 + 63];
      v43 = 8;
      v44 = v42 | (v41 << 8);
      v45 = v91;
      v91[15] = v44;
      do
      {
        v46 = v45[1];
        v47 = v45[14];
        v48 = *v45
            + v45[9]
            + ((v47 >> 10) ^ __ROL4__(v47, 13) ^ __ROL4__(v47, 15))
            + ((v46 >> 3) ^ __ROR4__(v46, 7) ^ __ROL4__(v46, 14));
        v45[16] = v48;
        v49 = v45[10]
            + ((v45[15] >> 10) ^ __ROL4__(v45[15], 13) ^ __ROL4__(v45[15], 15))
            + ((v45[2] >> 3) ^ __ROR4__(v45[2], 7) ^ __ROL4__(v45[2], 14))
            + v46;
        v45[17] = v49;
        v50 = v45[2]
            + v45[11]
            + ((v48 >> 10) ^ __ROL4__(v48, 13) ^ __ROL4__(v48, 15))
            + ((v45[3] >> 3) ^ __ROR4__(v45[3], 7) ^ __ROL4__(v45[3], 14));
        v45[18] = v50;
        v51 = v45[3]
            + v45[12]
            + ((v45[4] >> 3) ^ __ROR4__(v45[4], 7) ^ __ROL4__(v45[4], 14))
            + (__ROL4__(v49, 13) ^ __ROL4__(v49, 15) ^ (v49 >> 10));
        v45[19] = v51;
        v52 = v45[5];
        v45 += 6;
        v45[14] = *(v45 - 2)
                + v45[7]
                + ((v50 >> 10) ^ __ROL4__(v50, 13) ^ __ROL4__(v50, 15))
                + ((v52 >> 3) ^ __ROR4__(v52, 7) ^ __ROL4__(v52, 14));
        v45[15] = *(v45 - 1)
                + v47
                + ((v51 >> 10) ^ __ROL4__(v51, 13) ^ __ROL4__(v51, 15))
                + ((*v45 >> 3) ^ __ROR4__(*v45, 7) ^ __ROL4__(*v45, 14));
        --v43;
      }
      while ( v43 != 0 );
      v53 = v75;
      v54 = v11;
      v55 = v76;
      v56 = v77;
      v57 = v8;
      v58 = v74;
      v59 = v9;
      v60 = v78;
      v61 = 0;
      do
      {
        v62 = v60
            + v91[v61]
            + *(_DWORD *)((char *)&unk_1400189D0 + v61 * 4)
            + (v53 & v55 ^ v56 & ~v53)
            + (__ROR4__(v53, 6) ^ __ROL4__(v53, 7) ^ __ROR4__(v53, 11));
        v60 = v56;
        v63 = (v54 & v57 ^ v59 & (v54 ^ v57)) + (__ROR4__(v54, 2) ^ __ROL4__(v54, 10) ^ __ROR4__(v54, 13));
        v56 = v55;
        v55 = v53;
        ++v61;
        v53 = v62 + v58;
        v58 = v59;
        v59 = v57;
        v57 = v54;
        v54 = v63 + v62;
      }
      while ( v61 < 64 );
      v11 = v54 + v79;
      v64 = v57 + v72;
      v65 = v53 + v75;
      v66 = v59 + v73;
      v67 = v55 + v76;
      v68 = v58 + v74;
      v69 = v56 + v77;
      v70 = v60 + v78;
      v10 = v80 + 64;
      v79 = v11;
      v83 = v11;
      v72 = v64;
      v84 = v64;
      v73 = v66;
      v85 = v66;
      v74 = v68;
      v86 = v68;
      v75 = v65;
      v87 = v65;
      v76 = v67;
      v88 = v67;
      v77 = v69;
      v89 = v69;
      v78 = v70;
      v90 = v70;
      v80 = v10;
      if ( v10 >= v81 )
        break;
      v8 = v64;
      v9 = v66;
    }
    v4 = a3;
    v7 = v79;
  }
  else
  {
    v64 = -1150833019;
    v66 = 1013904242;
    v70 = 1541459225;
    v68 = -1521486534;
    v65 = 1359893119;
    v67 = -1694144372;
    v69 = 528734635;
  }
  *v4 = HIBYTE(v7);
  v4[1] = BYTE2(v7);
  v4[3] = v83;
  v4[4] = HIBYTE(v64);
  v4[5] = BYTE2(v64);
  v4[7] = v84;
  v4[8] = HIBYTE(v66);
  v4[9] = BYTE2(v66);
  v4[11] = v85;
  v4[12] = HIBYTE(v68);
  v4[13] = BYTE2(v68);
  v4[15] = v86;
  v4[16] = HIBYTE(v65);
  v4[17] = BYTE2(v65);
  v4[19] = v87;
  v4[20] = HIBYTE(v67);
  v4[21] = BYTE2(v67);
  v4[23] = v88;
  v4[24] = HIBYTE(v69);
  v4[25] = BYTE2(v69);
  v4[27] = v89;
  v4[28] = HIBYTE(v70);
  v4[29] = BYTE2(v70);
  v4[31] = v90;
  v4[2] = BYTE1(v7);
  v4[6] = BYTE1(v64);
  v4[10] = BYTE1(v66);
  v4[14] = BYTE1(v68);
  v4[18] = BYTE1(v65);
  v4[22] = BYTE1(v67);
  v4[26] = BYTE1(v69);
  v4[30] = BYTE1(v70);
  return v90;
}
