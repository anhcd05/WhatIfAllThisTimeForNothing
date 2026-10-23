// salsa20_block = sub_3D40 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_3D40(__int64 *a1, int *a2, __int64 a3, __int64 a4)
{
  int v4; // r14d
  int v5; // r13d
  int v6; // r12d
  int v7; // ebx
  __int64 v8; // r8
  unsigned __int64 v9; // rax
  __int64 v10; // r10
  __int64 v11; // r9
  int v12; // edi
  int v13; // esi
  int v14; // r15d
  int v15; // rsi^4
  unsigned __int64 v16; // rdx
  int v17; // esi
  int v18; // r10d
  int v19; // r8d
  int v20; // eax
  int v21; // ecx
  int v22; // ebp
  int v23; // r11d
  int v24; // r9d
  int v25; // r14d
  int v26; // r10d
  int v27; // r8d
  int v28; // r12d
  int v29; // ecx
  int v30; // r13d
  int v31; // edi
  int v32; // esi
  int v33; // edx
  int v34; // ebx
  int v35; // eax
  __int64 result; // rax
  int v37; // [rsp+0h] [rbp-DCh]
  int v38; // [rsp+4h] [rbp-D8h]
  unsigned __int64 v39; // [rsp+8h] [rbp-D4h]
  int v40; // [rsp+10h] [rbp-CCh]
  int v41; // [rsp+14h] [rbp-C8h]
  int v42; // [rsp+18h] [rbp-C4h]
  _DWORD v44[8]; // [rsp+24h] [rbp-B8h] BYREF
  __int64 v45; // [rsp+44h] [rbp-98h]
  int v46; // [rsp+4Ch] [rbp-90h]
  unsigned __int64 v47; // [rsp+50h] [rbp-8Ch]
  __int64 v48; // [rsp+58h] [rbp-84h]
  int v49; // [rsp+60h] [rbp-7Ch]
  _DWORD v50[2]; // [rsp+64h] [rbp-78h]
  unsigned __int64 v51; // [rsp+6Ch] [rbp-70h]
  int v52; // [rsp+74h] [rbp-68h]
  int v53; // [rsp+78h] [rbp-64h]
  int v54; // [rsp+7Ch] [rbp-60h]
  int v55; // [rsp+80h] [rbp-5Ch]
  int v56; // [rsp+84h] [rbp-58h]
  int v57; // [rsp+88h] [rbp-54h]
  int v58; // [rsp+8Ch] [rbp-50h]
  int v59; // [rsp+90h] [rbp-4Ch]
  int v60; // [rsp+94h] [rbp-48h]
  int v61; // [rsp+98h] [rbp-44h]
  int v62; // [rsp+9Ch] [rbp-40h]
  int v63; // [rsp+A0h] [rbp-3Ch]

  v4 = a3;
  v5 = 857760878;
  v6 = 1634760805;
  v7 = 2036477234;
  v8 = a1[1];
  v9 = a1[2];
  v10 = *a1;
  v11 = a1[3];
  v45 = a3;
  v12 = *a2;
  v13 = a2[1];
  *(_QWORD *)&v44[3] = v8;
  *(_QWORD *)&v44[1] = v10;
  v14 = v10;
  v40 = v13;
  v44[7] = v13;
  v15 = HIDWORD(a3);
  v47 = v9;
  v16 = HIDWORD(v9);
  v48 = v11;
  v44[0] = 1634760805;
  v44[5] = 857760878;
  v17 = v11;
  v46 = 2036477234;
  v49 = 1797285236;
  v44[6] = v12;
  v39 = __PAIR64__(v8, HIDWORD(v10));
  v18 = HIDWORD(v11);
  v42 = 10;
  v19 = HIDWORD(v8);
  v41 = v9;
  v20 = 1797285236;
  v21 = v15;
  do
  {
    v22 = v19 ^ __ROL4__(v16 + v6, 7);
    v23 = v21 ^ __ROL4__(v5 + v14, 7);
    v24 = v18 ^ __ROL4__(v12 + v7, 7);
    v25 = __ROL4__(v22 + v6, 9) ^ v4;
    v26 = v39 ^ __ROL4__(v24 + v7, 9);
    v37 = v16 ^ __ROL4__(v22 + v25, 13);
    v27 = v6 ^ __ROR4__(v25 + v37, 14);
    v38 = v17 ^ __ROL4__(v23 + v5, 9);
    v28 = v14 ^ __ROL4__(v23 + v38, 13);
    v29 = v5 ^ __ROR4__(v38 + v28, 14);
    v30 = v12 ^ __ROL4__(v24 + v26, 13);
    v31 = HIDWORD(v39) ^ __ROL4__(v41 + v20, 7);
    v32 = v40 ^ __ROL4__(v31 + v20, 9);
    v33 = v7 ^ __ROR4__(v26 + v30, 14);
    v34 = v41 ^ __ROL4__(v31 + v32, 13);
    v35 = __ROR4__(v32 + v34, 14) ^ v20;
    v14 = v28 ^ __ROL4__(v27 + v31, 7);
    LODWORD(v39) = v26 ^ __ROL4__(v27 + v14, 9);
    HIDWORD(v39) = v31 ^ __ROL4__(v14 + v39, 13);
    v12 = v30 ^ __ROL4__(v22 + v29, 7);
    v6 = v27 ^ __ROR4__(HIDWORD(v39) + v39, 14);
    v40 = v32 ^ __ROL4__(v29 + v12, 9);
    v19 = v22 ^ __ROL4__(v12 + v40, 13);
    v5 = v29 ^ __ROR4__(v40 + v19, 14);
    v41 = v34 ^ __ROL4__(v23 + v33, 7);
    v4 = __ROL4__(v33 + v41, 9) ^ v25;
    v21 = v23 ^ __ROL4__(v41 + v4, 13);
    v7 = v33 ^ __ROR4__(v4 + v21, 14);
    LODWORD(v16) = v37 ^ __ROL4__(v24 + v35, 7);
    v17 = v38 ^ __ROL4__(v35 + v16, 9);
    v18 = v24 ^ __ROL4__(v16 + v17, 13);
    v20 = __ROR4__(v17 + v18, 14) ^ v35;
    --v42;
  }
  while ( v42 != 0 );
  v50[1] = v14;
  v54 = v12;
  v51 = v39;
  v55 = v40;
  v50[0] = v6;
  v52 = v19;
  v53 = v5;
  v59 = v41;
  v56 = v4;
  v57 = v21;
  v58 = v7;
  v60 = v16;
  v61 = v17;
  v62 = v18;
  v63 = v20;
  for ( result = 0; result != 16; result += 4 )
    *(__m128i *)(a4 + result * 4) = _mm_add_epi32(
                                      _mm_load_si128((const __m128i *)&v44[result]),
                                      *(__m128i *)&v50[result]);
  return result * 4;
}
