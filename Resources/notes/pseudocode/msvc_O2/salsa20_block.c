void __fastcall salsa20_block(
        const unsigned int *key,
        const unsigned int *nonce,
        unsigned __int64 counter,
        unsigned __int8 *out)
{
  __int64 v4; // kr00_8
  int v5; // r11d
  int v6; // r13d
  int v7; // r10d
  int v8; // r12d
  int v9; // r14d
  int v10; // edi
  int v11; // edx
  int v12; // esi
  int v13; // ebx
  int v14; // r9d
  int v15; // r15d
  int v16; // ebx
  int v17; // r12d
  int v18; // r8d
  int v19; // edi
  int v20; // eax
  int v21; // r13d
  int v22; // edx
  int v23; // ecx
  int v24; // r10d
  int v25; // r11d
  int v26; // esi
  int v27; // r14d
  int v28; // ecx
  int v29; // r15d
  int v30; // eax
  int v31; // r11d
  int v32; // esi
  int v33; // r8d
  bool v34; // zf
  int v35; // [rsp+0h] [rbp-100h]
  int v36; // [rsp+4h] [rbp-FCh]
  __int64 v37; // [rsp+8h] [rbp-F8h]
  int v38; // [rsp+10h] [rbp-F0h]
  int v39; // [rsp+14h] [rbp-ECh]
  int v40; // [rsp+18h] [rbp-E8h]
  int v41; // [rsp+1Ch] [rbp-E4h]
  unsigned int v42; // [rsp+20h] [rbp-E0h]
  int v43; // [rsp+24h] [rbp-DCh]
  int v44; // [rsp+28h] [rbp-D8h]
  int v45; // [rsp+34h] [rbp-CCh]
  int v46; // [rsp+38h] [rbp-C8h]
  int v47; // [rsp+3Ch] [rbp-C4h]
  int v48; // [rsp+48h] [rbp-B8h]
  unsigned int v49; // [rsp+54h] [rbp-ACh]
  unsigned int v50; // [rsp+58h] [rbp-A8h]
  unsigned int v51; // [rsp+5Ch] [rbp-A4h]
  unsigned int v52; // [rsp+60h] [rbp-A0h]
  __int64 v53; // [rsp+68h] [rbp-98h]
  int v55; // [rsp+78h] [rbp-88h]
  unsigned __int64 v56; // [rsp+80h] [rbp-80h]
  __int64 s_8; // [rsp+98h] [rbp-68h]

  v55 = counter;
  v47 = *key;
  v56 = HIDWORD(counter);
  v49 = key[4];
  s_8 = *(_QWORD *)(key + 1);
  v50 = key[5];
  v51 = key[6];
  v52 = key[7];
  v4 = *(_QWORD *)nonce;
  v5 = *nonce;
  v6 = 857760878;
  v7 = *key;
  v8 = 1634760805;
  v9 = 1797285236;
  v10 = v51;
  v11 = v50;
  v42 = v52;
  v12 = 2036477234;
  v13 = counter;
  v40 = HIDWORD(counter);
  v39 = HIDWORD(v4);
  v38 = key[3];
  v14 = v49;
  v37 = s_8;
  v48 = v38;
  v53 = 10;
  v36 = 1797285236;
  v35 = 2036477234;
  while ( 1 )
  {
    v15 = v38 ^ __ROL4__(v8 + v11, 7);
    v45 = v13 ^ __ROL4__(v15 + v8, 9);
    v46 = v11 ^ __ROL4__(v45 + v15, 13);
    v16 = v8 ^ __ROR4__(v46 + v45, 14);
    v17 = v40 ^ __ROL4__(v7 + v6, 7);
    v41 = v10 ^ __ROL4__(v17 + v6, 9);
    v18 = v7 ^ __ROL4__(v41 + v17, 13);
    v19 = v6 ^ __ROR4__(v18 + v41, 14);
    v20 = HIDWORD(v37) ^ __ROL4__(v14 + v9, 7);
    v21 = v42 ^ __ROL4__(v5 + v12, 7);
    v22 = v39 ^ __ROL4__(v20 + v9, 9);
    v23 = v37 ^ __ROL4__(v12 + v21, 9);
    v24 = v5 ^ __ROL4__(v23 + v21, 13);
    v25 = v14 ^ __ROL4__(v22 + v20, 13);
    v26 = v35 ^ __ROR4__(v24 + v23, 14);
    v27 = v36 ^ __ROR4__(v25 + v22, 14);
    v44 = v18 ^ __ROL4__(v16 + v20, 7);
    LODWORD(v37) = v23 ^ __ROL4__(v16 + v44, 9);
    HIDWORD(v37) = v20 ^ __ROL4__(v44 + v37, 13);
    v28 = v24 ^ __ROL4__(v19 + v15, 7);
    v43 = v16 ^ __ROR4__(HIDWORD(v37) + v37, 14);
    v39 = v22 ^ __ROL4__(v28 + v19, 9);
    v38 = v15 ^ __ROL4__(v39 + v28, 13);
    v7 = v44;
    v29 = v19 ^ __ROR4__(v38 + v39, 14);
    v14 = v25 ^ __ROL4__(v26 + v17, 7);
    v11 = v46 ^ __ROL4__(v27 + v21, 7);
    v13 = v45 ^ __ROL4__(v14 + v26, 9);
    v10 = v41 ^ __ROL4__(v27 + v11, 9);
    v30 = v17 ^ __ROL4__(v13 + v14, 13);
    v8 = v43;
    v40 = v30;
    v31 = v26 ^ __ROR4__(v30 + v13, 14);
    v32 = v21 ^ __ROL4__(v10 + v11, 13);
    v35 = v31;
    v42 = v32;
    v33 = v27 ^ __ROR4__(v10 + v32, 14);
    v34 = v53-- == 1;
    v36 = v33;
    if ( v34 )
      break;
    v5 = v28;
    v9 = v33;
    v12 = v35;
    v6 = v29;
  }
  *(_DWORD *)out = v43 + 1634760805;
  *((_DWORD *)out + 1) = v44 + v47;
  *((_DWORD *)out + 2) = s_8 + v37;
  *((_DWORD *)out + 3) = HIDWORD(v37) + HIDWORD(s_8);
  *((_DWORD *)out + 4) = v38 + v48;
  *((_DWORD *)out + 5) = v29 + 857760878;
  *((_DWORD *)out + 6) = v28 + v4;
  *((_DWORD *)out + 7) = v39 + HIDWORD(v4);
  *((_DWORD *)out + 8) = v13 + v55;
  *((_DWORD *)out + 9) = v30 + v56;
  *((_DWORD *)out + 10) = v31 + 2036477234;
  *((_DWORD *)out + 11) = v49 + v14;
  *((_DWORD *)out + 12) = v11 + v50;
  *((_DWORD *)out + 13) = v10 + v51;
  *((_DWORD *)out + 14) = v32 + v52;
  *((_DWORD *)out + 15) = v33 + 1797285236;
}
