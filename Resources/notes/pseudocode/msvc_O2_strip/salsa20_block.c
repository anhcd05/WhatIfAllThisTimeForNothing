// salsa20_block = sub_1400041F0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400041F0(int *a1, __int64 *a2, unsigned __int64 a3, _DWORD *a4)
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
  __int64 result; // rax
  int v36; // [rsp+0h] [rbp-100h]
  int v37; // [rsp+4h] [rbp-FCh]
  __int64 v38; // [rsp+8h] [rbp-F8h]
  int v39; // [rsp+10h] [rbp-F0h]
  int v40; // [rsp+14h] [rbp-ECh]
  int v41; // [rsp+18h] [rbp-E8h]
  int v42; // [rsp+1Ch] [rbp-E4h]
  int v43; // [rsp+20h] [rbp-E0h]
  int v44; // [rsp+24h] [rbp-DCh]
  int v45; // [rsp+28h] [rbp-D8h]
  int v46; // [rsp+34h] [rbp-CCh]
  int v47; // [rsp+38h] [rbp-C8h]
  int v48; // [rsp+3Ch] [rbp-C4h]
  int v49; // [rsp+48h] [rbp-B8h]
  int v50; // [rsp+54h] [rbp-ACh]
  int v51; // [rsp+58h] [rbp-A8h]
  int v52; // [rsp+5Ch] [rbp-A4h]
  int v53; // [rsp+60h] [rbp-A0h]
  __int64 v54; // [rsp+68h] [rbp-98h]
  int v56; // [rsp+78h] [rbp-88h]
  unsigned __int64 v57; // [rsp+80h] [rbp-80h]
  __int64 v58; // [rsp+98h] [rbp-68h]

  v56 = a3;
  v48 = *a1;
  v57 = HIDWORD(a3);
  v50 = a1[4];
  v58 = *(_QWORD *)(a1 + 1);
  v51 = a1[5];
  v52 = a1[6];
  v53 = a1[7];
  v4 = *a2;
  v5 = *(_DWORD *)a2;
  v6 = 857760878;
  v7 = *a1;
  v8 = 1634760805;
  v9 = 1797285236;
  v10 = v52;
  v11 = v51;
  v43 = v53;
  v12 = 2036477234;
  v13 = a3;
  v41 = HIDWORD(a3);
  v40 = HIDWORD(v4);
  v39 = a1[3];
  v14 = v50;
  v38 = v58;
  v49 = v39;
  v54 = 10;
  v37 = 1797285236;
  v36 = 2036477234;
  while ( 1 )
  {
    v15 = v39 ^ __ROL4__(v8 + v11, 7);
    v46 = v13 ^ __ROL4__(v15 + v8, 9);
    v47 = v11 ^ __ROL4__(v46 + v15, 13);
    v16 = v8 ^ __ROR4__(v47 + v46, 14);
    v17 = v41 ^ __ROL4__(v7 + v6, 7);
    v42 = v10 ^ __ROL4__(v17 + v6, 9);
    v18 = v7 ^ __ROL4__(v42 + v17, 13);
    v19 = v6 ^ __ROR4__(v18 + v42, 14);
    v20 = HIDWORD(v38) ^ __ROL4__(v14 + v9, 7);
    v21 = v43 ^ __ROL4__(v5 + v12, 7);
    v22 = v40 ^ __ROL4__(v20 + v9, 9);
    v23 = v38 ^ __ROL4__(v12 + v21, 9);
    v24 = v5 ^ __ROL4__(v23 + v21, 13);
    v25 = v14 ^ __ROL4__(v22 + v20, 13);
    v26 = v36 ^ __ROR4__(v24 + v23, 14);
    v27 = v37 ^ __ROR4__(v25 + v22, 14);
    v45 = v18 ^ __ROL4__(v16 + v20, 7);
    LODWORD(v38) = v23 ^ __ROL4__(v16 + v45, 9);
    HIDWORD(v38) = v20 ^ __ROL4__(v45 + v38, 13);
    v28 = v24 ^ __ROL4__(v19 + v15, 7);
    v44 = v16 ^ __ROR4__(HIDWORD(v38) + v38, 14);
    v40 = v22 ^ __ROL4__(v28 + v19, 9);
    v39 = v15 ^ __ROL4__(v40 + v28, 13);
    v7 = v45;
    v29 = v19 ^ __ROR4__(v39 + v40, 14);
    v14 = v25 ^ __ROL4__(v26 + v17, 7);
    v11 = v47 ^ __ROL4__(v27 + v21, 7);
    v13 = v46 ^ __ROL4__(v14 + v26, 9);
    v10 = v42 ^ __ROL4__(v27 + v11, 9);
    v30 = v17 ^ __ROL4__(v13 + v14, 13);
    v8 = v44;
    v41 = v30;
    v31 = v26 ^ __ROR4__(v30 + v13, 14);
    v32 = v21 ^ __ROL4__(v10 + v11, 13);
    v36 = v31;
    v43 = v32;
    v33 = v27 ^ __ROR4__(v10 + v32, 14);
    v34 = v54-- == 1;
    v37 = v33;
    if ( v34 )
      break;
    v5 = v28;
    v9 = v33;
    v12 = v36;
    v6 = v29;
  }
  *a4 = v44 + 1634760805;
  a4[1] = v45 + v48;
  a4[2] = v58 + v38;
  a4[3] = HIDWORD(v38) + HIDWORD(v58);
  a4[4] = v39 + v49;
  a4[5] = v29 + 857760878;
  a4[6] = v28 + v4;
  a4[7] = v40 + HIDWORD(v4);
  a4[8] = v13 + v56;
  a4[9] = v30 + v57;
  a4[10] = v31 + 2036477234;
  a4[11] = v50 + v14;
  a4[12] = v11 + v51;
  a4[13] = v10 + v52;
  a4[14] = v32 + v53;
  result = (unsigned int)(v33 + 1797285236);
  a4[15] = result;
  return result;
}
