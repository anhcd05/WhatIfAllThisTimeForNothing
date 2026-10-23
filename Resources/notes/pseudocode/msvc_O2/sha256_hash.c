void __fastcall sha256_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  unsigned __int64 v3; // rsi
  unsigned __int8 *v4; // r13
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
  unsigned int *v45; // rax
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
  unsigned int v62; // r8d
  int v63; // edx
  int v64; // ecx
  int v65; // r9d
  int v66; // edx
  int v67; // r10d
  int v68; // r8d
  int v69; // r11d
  int v70; // ebx
  int v71; // [rsp+20h] [rbp-E0h]
  int v72; // [rsp+24h] [rbp-DCh]
  int v73; // [rsp+28h] [rbp-D8h]
  int v74; // [rsp+2Ch] [rbp-D4h]
  int v75; // [rsp+30h] [rbp-D0h]
  int v76; // [rsp+34h] [rbp-CCh]
  int v77; // [rsp+38h] [rbp-C8h]
  int v78; // [rsp+3Ch] [rbp-C4h]
  unsigned __int64 v79; // [rsp+40h] [rbp-C0h]
  unsigned __int64 v80; // [rsp+48h] [rbp-B8h]
  char H; // [rsp+58h] [rbp-A8h]
  char H_4; // [rsp+5Ch] [rbp-A4h]
  char H_8; // [rsp+60h] [rbp-A0h]
  char H_12; // [rsp+64h] [rbp-9Ch]
  char H_16; // [rsp+68h] [rbp-98h]
  char H_20; // [rsp+6Ch] [rbp-94h]
  char H_24; // [rsp+70h] [rbp-90h]
  char H_28; // [rsp+74h] [rbp-8Ch]
  unsigned int w[64]; // [rsp+80h] [rbp-80h] BYREF
  unsigned __int8 buf[320]; // [rsp+180h] [rbp+80h] BYREF

  v3 = 8 * n;
  v4 = out;
  v80 = ((n + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v73 = -1521486534;
  H_12 = 58;
  v7 = 1779033703;
  v78 = 1779033703;
  v74 = 1359893119;
  v8 = -1150833019;
  H_16 = 127;
  v9 = 1013904242;
  H = 103;
  v75 = -1694144372;
  H_20 = -116;
  v71 = -1150833019;
  v76 = 528734635;
  H_24 = -85;
  v77 = 1541459225;
  H_28 = 25;
  H_4 = -123;
  v72 = 1013904242;
  H_8 = 114;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  v10 = 0;
  v79 = 0;
  *((_BYTE *)&w[63] + v80 + 3) = v3;
  *((_BYTE *)&w[63] + v80 + 2) = BYTE1(v3);
  *((_BYTE *)&w[63] + v80 + 1) = BYTE2(v3);
  *((_BYTE *)&w[63] + v80) = BYTE3(v3);
  *((_BYTE *)&w[62] + v80 + 3) = BYTE4(v3);
  *((_BYTE *)&w[62] + v80 + 2) = BYTE5(v3);
  *((_BYTE *)&w[62] + v80 + 1) = BYTE6(v3);
  *((_BYTE *)&w[62] + v80) = HIBYTE(v3);
  if ( v80 != 0 )
  {
    v11 = 1779033703;
    while ( 1 )
    {
      v12 = buf[v10 + 5];
      w[0] = buf[v10 + 3] | ((buf[v10 + 2] | ((buf[v10 + 1] | (buf[v10] << 8)) << 8)) << 8);
      v13 = buf[v10 + 7] | ((buf[v10 + 6] | ((v12 | (buf[v10 + 4] << 8)) << 8)) << 8);
      v14 = buf[v10 + 9];
      w[1] = v13;
      v15 = buf[v10 + 11] | ((buf[v10 + 10] | ((v14 | (buf[v10 + 8] << 8)) << 8)) << 8);
      v16 = buf[v10 + 12];
      w[2] = v15;
      v17 = buf[v10 + 15] | ((buf[v10 + 14] | (((v16 << 8) | buf[v10 + 13]) << 8)) << 8);
      v18 = buf[v10 + 17];
      w[3] = v17;
      v19 = buf[v10 + 19] | ((buf[v10 + 18] | ((v18 | (buf[v10 + 16] << 8)) << 8)) << 8);
      v20 = buf[v10 + 21];
      w[4] = v19;
      v21 = buf[v10 + 23] | ((buf[v10 + 22] | ((v20 | (buf[v10 + 20] << 8)) << 8)) << 8);
      v22 = buf[v10 + 25];
      w[5] = v21;
      v23 = buf[v10 + 27] | ((buf[v10 + 26] | ((v22 | (buf[v10 + 24] << 8)) << 8)) << 8);
      v24 = buf[v10 + 29];
      w[6] = v23;
      v25 = buf[v10 + 31] | ((buf[v10 + 30] | ((v24 | (buf[v10 + 28] << 8)) << 8)) << 8);
      v26 = buf[v10 + 33];
      w[7] = v25;
      v27 = buf[v10 + 35] | ((buf[v10 + 34] | ((v26 | (buf[v10 + 32] << 8)) << 8)) << 8);
      v28 = buf[v10 + 37];
      w[8] = v27;
      v29 = buf[v10 + 39] | ((buf[v10 + 38] | ((v28 | (buf[v10 + 36] << 8)) << 8)) << 8);
      v30 = buf[v10 + 41];
      w[9] = v29;
      v31 = buf[v10 + 43] | ((buf[v10 + 42] | ((v30 | (buf[v10 + 40] << 8)) << 8)) << 8);
      v32 = buf[v10 + 45];
      w[10] = v31;
      v33 = buf[v10 + 47] | ((buf[v10 + 46] | ((v32 | (buf[v10 + 44] << 8)) << 8)) << 8);
      v34 = buf[v10 + 49];
      w[11] = v33;
      v35 = buf[v10 + 51] | ((buf[v10 + 50] | ((v34 | (buf[v10 + 48] << 8)) << 8)) << 8);
      v36 = buf[v10 + 53];
      w[12] = v35;
      v37 = buf[v10 + 55] | ((buf[v10 + 54] | ((v36 | (buf[v10 + 52] << 8)) << 8)) << 8);
      v38 = buf[v10 + 57];
      w[13] = v37;
      v39 = buf[v10 + 59] | ((buf[v10 + 58] | ((v38 | (buf[v10 + 56] << 8)) << 8)) << 8);
      v40 = buf[v10 + 61];
      w[14] = v39;
      v41 = buf[v10 + 62] | ((v40 | (buf[v10 + 60] << 8)) << 8);
      v42 = buf[v10 + 63];
      v43 = 8;
      v44 = v42 | (v41 << 8);
      v45 = w;
      w[15] = v44;
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
      v53 = v74;
      v54 = v11;
      v55 = v75;
      v56 = v76;
      v57 = v8;
      v58 = v73;
      v59 = v9;
      v60 = v77;
      v61 = 0;
      do
      {
        v62 = v60
            + w[v61]
            + SHA256_K[v61]
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
      v11 = v54 + v78;
      v64 = v57 + v71;
      v65 = v53 + v74;
      v66 = v59 + v72;
      v67 = v55 + v75;
      v68 = v58 + v73;
      v69 = v56 + v76;
      v70 = v60 + v77;
      v10 = v79 + 64;
      v78 = v11;
      H = v11;
      v71 = v64;
      H_4 = v64;
      v72 = v66;
      H_8 = v66;
      v73 = v68;
      H_12 = v68;
      v74 = v65;
      H_16 = v65;
      v75 = v67;
      H_20 = v67;
      v76 = v69;
      H_24 = v69;
      v77 = v70;
      H_28 = v70;
      v79 = v10;
      if ( v10 >= v80 )
        break;
      v8 = v64;
      v9 = v66;
    }
    v4 = out;
    v7 = v78;
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
  v4[3] = H;
  v4[4] = HIBYTE(v64);
  v4[5] = BYTE2(v64);
  v4[7] = H_4;
  v4[8] = HIBYTE(v66);
  v4[9] = BYTE2(v66);
  v4[11] = H_8;
  v4[12] = HIBYTE(v68);
  v4[13] = BYTE2(v68);
  v4[15] = H_12;
  v4[16] = HIBYTE(v65);
  v4[17] = BYTE2(v65);
  v4[19] = H_16;
  v4[20] = HIBYTE(v67);
  v4[21] = BYTE2(v67);
  v4[23] = H_20;
  v4[24] = HIBYTE(v69);
  v4[25] = BYTE2(v69);
  v4[27] = H_24;
  v4[28] = HIBYTE(v70);
  v4[29] = BYTE2(v70);
  v4[31] = H_28;
  v4[2] = BYTE1(v7);
  v4[6] = BYTE1(v64);
  v4[10] = BYTE1(v66);
  v4[14] = BYTE1(v68);
  v4[18] = BYTE1(v65);
  v4[22] = BYTE1(v67);
  v4[26] = BYTE1(v69);
  v4[30] = BYTE1(v70);
}
