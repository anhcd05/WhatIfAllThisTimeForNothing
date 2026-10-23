void __fastcall chacha20_block(const unsigned int *key, unsigned int counter, unsigned int *nonce, char *out)
{
  unsigned int v4; // eax
  __int128 v5; // xmm1
  __int128 v6; // xmm2
  unsigned int v7; // eax
  int v8; // r13d
  unsigned int v9; // r12d
  unsigned int v10; // r15d
  unsigned int v11; // r11d
  unsigned int v12; // esi
  unsigned int v13; // edi
  unsigned int v14; // ebx
  unsigned int v15; // r14d
  unsigned int v16; // r8d
  unsigned int v17; // r10d
  unsigned int v18; // r9d
  unsigned int v19; // eax
  int v20; // r10d
  int v21; // ecx
  int v22; // edi
  int v23; // edx
  int v24; // r15d
  unsigned int v25; // eax
  int v26; // r8d
  int v27; // ecx
  int v28; // esi
  int v29; // edi
  unsigned int v30; // eax
  int v31; // r14d
  int v32; // r12d
  int v33; // r8d
  int v34; // r11d
  int v35; // r10d
  int v36; // esi
  int v37; // r10d
  unsigned int v38; // eax
  int v39; // r13d
  int v40; // ebx
  int v41; // r8d
  int v42; // r11d
  int v43; // r14d
  int v44; // eax
  int v45; // r9d
  int v46; // ecx
  int v47; // ebx
  int v48; // edx
  int v49; // eax
  int v50; // r8d
  int v51; // eax
  int v52; // r10d
  int v53; // ecx
  int v54; // r11d
  int v55; // eax
  int v56; // r8d
  int v57; // ecx
  int v58; // r9d
  unsigned int v59; // eax
  int v60; // r8d
  int v61; // eax
  int v62; // eax
  int v63; // ecx
  __int64 v64; // r8
  __int64 v65; // r10
  __int64 v66; // r9
  char *v67; // rax
  __int64 v68; // r11
  __int64 i; // rdx
  int v70; // [rsp+0h] [rbp-99h]
  unsigned int v71; // [rsp+4h] [rbp-95h]
  int v72; // [rsp+4h] [rbp-95h]
  int v73; // [rsp+8h] [rbp-91h]
  int v74; // [rsp+Ch] [rbp-8Dh]
  int v75; // [rsp+10h] [rbp-89h]
  int v76; // [rsp+14h] [rbp-85h]
  int v77; // [rsp+18h] [rbp-81h]
  __int64 v78; // [rsp+28h] [rbp-71h]
  unsigned int x[16]; // [rsp+40h] [rbp-59h] BYREF
  unsigned int s[16]; // [rsp+80h] [rbp-19h] BYREF

  v4 = *nonce;
  v5 = *((_OWORD *)key + 1);
  qmemcpy(s, "expand 32-byte k", 16);
  v6 = *(_OWORD *)key;
  *(_OWORD *)&s[12] = 0;
  s[13] = v4;
  s[14] = nonce[1];
  v7 = nonce[2];
  *(_OWORD *)&x[8] = v5;
  v8 = DWORD2(v5);
  v9 = DWORD1(v5);
  v10 = v5;
  *(_OWORD *)&x[4] = v6;
  v11 = DWORD2(v6);
  v12 = DWORD1(v6);
  v13 = v6;
  s[15] = v7;
  *(_OWORD *)x = *(_OWORD *)s;
  s[12] = counter;
  *(_OWORD *)&x[12] = *(_OWORD *)&s[12];
  v14 = v7;
  v15 = s[14];
  v16 = s[13];
  v17 = counter;
  v74 = HIDWORD(v5);
  v18 = HIDWORD(v6);
  v71 = 1797285236;
  *(_OWORD *)&s[4] = v6;
  *(_OWORD *)&s[8] = v5;
  v78 = 10;
  v70 = 2036477234;
  do
  {
    v19 = v13 + x[0];
    v20 = __ROL4__((v13 + x[0]) ^ v17, 16);
    v21 = v10 + v20;
    v22 = __ROL4__((v10 + v20) ^ v13, 12);
    v23 = v22 + v19;
    v24 = __ROL4__(v20 ^ (v22 + v19), 8);
    v75 = v21 + v24;
    v76 = __ROL4__(v22 ^ (v21 + v24), 7);
    v25 = v12 + x[1];
    v26 = __ROL4__((v12 + x[1]) ^ v16, 16);
    v27 = v9 + v26;
    v28 = __ROL4__((v9 + v26) ^ v12, 12);
    v29 = v28 + v25;
    v30 = v11 + v70;
    v31 = __ROL4__((v11 + v70) ^ v15, 16);
    v32 = __ROL4__(v26 ^ v29, 8);
    v33 = v31 + v8;
    v34 = __ROL4__((v31 + v8) ^ v11, 12);
    v77 = v32 + v27;
    v35 = v28 ^ (v32 + v27);
    v36 = v34 + v30;
    v37 = __ROL4__(v35, 7);
    v38 = v18 + v71;
    v39 = __ROL4__(v31 ^ v36, 8);
    v40 = __ROL4__((v18 + v71) ^ v14, 16);
    v41 = v39 + v33;
    v72 = __ROL4__((v40 + v74) ^ v18, 12);
    v42 = __ROL4__(v34 ^ v41, 7);
    v43 = v72 + v38;
    v44 = __ROL4__(v40 ^ (v72 + v38), 8);
    v45 = v44 + v40 + v74;
    v46 = v23 + v37;
    v47 = __ROL4__(v72 ^ v45, 7);
    v48 = __ROL4__(v44 ^ (v23 + v37), 16);
    v49 = v41 + v48;
    v50 = __ROL4__(v37 ^ (v41 + v48), 12);
    x[0] = v50 + v46;
    x[15] = __ROL4__(v48 ^ (v50 + v46), 8);
    v73 = x[15] + v49;
    x[10] = x[15] + v49;
    x[5] = __ROL4__(v50 ^ (x[15] + v49), 7);
    v51 = v29 + v42;
    v52 = __ROL4__(v24 ^ (v29 + v42), 16);
    v53 = v52 + v45;
    v54 = __ROL4__(v42 ^ (v52 + v45), 12);
    x[1] = v54 + v51;
    v17 = __ROL4__((v54 + v51) ^ v52, 8);
    v74 = v53 + v17;
    x[11] = v53 + v17;
    v55 = v36 + v47;
    v12 = x[5];
    v11 = __ROL4__((v53 + v17) ^ v54, 7);
    v56 = __ROL4__(v32 ^ v55, 16);
    v57 = v56 + v75;
    x[6] = v11;
    v58 = __ROL4__(v47 ^ (v56 + v75), 12);
    v59 = v58 + v55;
    v60 = v59 ^ v56;
    v70 = v59;
    x[2] = v59;
    v61 = v39 ^ (v76 + v43);
    v16 = __ROL4__(v60, 8);
    v8 = v73;
    v62 = __ROL4__(v61, 16);
    v10 = v57 + v16;
    v63 = __ROL4__(v76 ^ (v62 + v77), 12);
    v18 = __ROL4__(v10 ^ v58, 7);
    v71 = v63 + v76 + v43;
    x[3] = v71;
    v14 = x[15];
    v15 = __ROL4__(v62 ^ v71, 8);
    v9 = v15 + v62 + v77;
    x[7] = v18;
    x[9] = v9;
    v13 = __ROL4__(v63 ^ v9, 7);
    --v78;
  }
  while ( v78 != 0 );
  x[13] = v16;
  x[12] = v17;
  x[4] = v13;
  v64 = (char *)x - out;
  x[14] = v15;
  v65 = (char *)&x[1] - out;
  x[8] = v10;
  v66 = (char *)s - out;
  v67 = out + 8;
  v68 = (char *)&s[1] - out;
  for ( i = 4; i != 0; --i )
  {
    *((_DWORD *)v67 - 2) = *(_DWORD *)&v67[v64 - 8] + *(_DWORD *)&v67[v66 - 8];
    *((_DWORD *)v67 - 1) = *(_DWORD *)&v67[v65 - 8] + *(_DWORD *)&v67[v68 - 8];
    *(_DWORD *)v67 = *(_DWORD *)&v67[v64] + *(_DWORD *)&v67[v66];
    *((_DWORD *)v67 + 1) = *(_DWORD *)&v67[v65] + *(_DWORD *)&v67[v68];
    v67 += 16;
  }
}
