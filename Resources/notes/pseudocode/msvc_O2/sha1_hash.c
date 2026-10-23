void __fastcall sha1_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  unsigned __int8 *v3; // r14
  size_t v5; // rsi
  int v7; // r15d
  int v8; // r12d
  int v9; // r13d
  size_t v10; // rdx
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
  unsigned int *v39; // rdi
  int v40; // ecx
  __int64 v41; // rsi
  int v42; // eax
  int v43; // edx
  unsigned int v44; // edx
  unsigned int v45; // ecx
  unsigned int v46; // r9d
  int v47; // r9d
  unsigned int v48; // r8d
  int v49; // r8d
  unsigned int v50; // eax
  int v51; // ebx
  int v52; // edi
  int v53; // r8d
  int v54; // edx
  int v55; // r10d
  __int64 v56; // r9
  int v57; // r11d
  int v58; // eax
  unsigned int v59; // ecx
  int v60; // ecx
  int v61; // esi
  int v62; // [rsp+20h] [rbp-E0h]
  int v63; // [rsp+24h] [rbp-DCh]
  size_t v64; // [rsp+28h] [rbp-D8h]
  size_t v65; // [rsp+30h] [rbp-D0h]
  unsigned int w[80]; // [rsp+40h] [rbp-C0h] BYREF
  unsigned __int8 buf[320]; // [rsp+180h] [rbp+80h] BYREF

  v63 = 271733878;
  v62 = -1009589776;
  v3 = out;
  v65 = ((n + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  v5 = 8 * n;
  v7 = 1732584193;
  v8 = -271733879;
  v9 = -1732584194;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  v10 = 0;
  buf[n] = 0x80;
  v64 = 0;
  *((_BYTE *)&w[79] + v65 + 3) = v5;
  *((_BYTE *)&w[79] + v65 + 2) = BYTE1(v5);
  *((_BYTE *)&w[79] + v65 + 1) = BYTE2(v5);
  *((_BYTE *)&w[79] + v65) = BYTE3(v5);
  *((_BYTE *)&w[78] + v65 + 3) = BYTE4(v5);
  *((_BYTE *)&w[78] + v65 + 2) = BYTE5(v5);
  *((_BYTE *)&w[78] + v65 + 1) = BYTE6(v5);
  *((_BYTE *)&w[78] + v65) = HIBYTE(v5);
  if ( v65 == 0 )
  {
    v61 = -1009589776;
    goto LABEL_18;
  }
  v11 = 271733878;
  do
  {
    v12 = buf[v10 + 5];
    w[0] = buf[v10 + 3] | ((buf[v10 + 2] | ((buf[v10 + 1] | (buf[v10] << 8)) << 8)) << 8);
    v13 = buf[v10 + 7] | ((buf[v10 + 6] | ((v12 | (buf[v10 + 4] << 8)) << 8)) << 8);
    v14 = buf[v10 + 9];
    w[1] = v13;
    v15 = buf[v10 + 11] | ((buf[v10 + 10] | ((v14 | (buf[v10 + 8] << 8)) << 8)) << 8);
    v16 = buf[v10 + 13];
    w[2] = v15;
    v17 = buf[v10 + 15] | ((buf[v10 + 14] | ((v16 | (buf[v10 + 12] << 8)) << 8)) << 8);
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
    v39 = &w[2];
    v40 = buf[v10 + 59] | ((buf[v10 + 58] | ((v38 | (buf[v10 + 56] << 8)) << 8)) << 8);
    v41 = 8;
    v42 = buf[v10 + 61];
    w[14] = v40;
    w[15] = buf[v10 + 63] | ((buf[v10 + 62] | ((v42 | (buf[v10 + 60] << 8)) << 8)) << 8);
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
    v52 = v62;
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
      v59 = w[v56++] + __ROL4__(v51, 5);
      v60 = v52 + v58 + v57 + v59;
      v52 = v55;
      v55 = v54;
      v54 = __ROR4__(v53, 2);
      v53 = v51;
      v51 = v60;
    }
    while ( v56 < 80 );
    v9 += v54;
    v61 = v52 + v62;
    v7 += v60;
    v10 = v64 + 64;
    v62 += v52;
    v8 += v53;
    v64 = v10;
    v11 += v55;
  }
  while ( v10 < v65 );
  v63 = v11;
  v3 = out;
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
  v3[12] = HIBYTE(v63);
  v3[13] = BYTE2(v63);
  v3[14] = BYTE1(v63);
  v3[16] = HIBYTE(v61);
  v3[17] = BYTE2(v61);
  v3[18] = BYTE1(v61);
  v3[3] = v7;
  v3[7] = v8;
  v3[11] = v9;
  v3[15] = v63;
  v3[19] = v61;
}
