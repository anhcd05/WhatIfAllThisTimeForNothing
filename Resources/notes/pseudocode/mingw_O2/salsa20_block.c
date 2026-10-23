__int64 __fastcall salsa20_block(__int64 *a1, int *a2, __int64 a3, __int64 a4)
{
  int v4; // edi
  int v5; // r13d
  int v6; // r12d
  __int64 v7; // r10
  unsigned __int64 v8; // rax
  __int64 v9; // rbx
  unsigned __int64 v10; // r11
  int v11; // r15d
  int v12; // r9d
  int v13; // r14d
  unsigned __int64 v14; // rdx
  int v15; // ecx
  int v16; // r8d
  unsigned __int64 v17; // r11
  int v18; // ebx
  int v19; // r10d
  int v20; // ebp
  int v21; // esi
  int v22; // r14d
  int v23; // ebx
  int v24; // r12d
  int v25; // ecx
  int v26; // r11d
  int v27; // r13d
  int v28; // r9d
  int v29; // r8d
  int v30; // edx
  int v31; // edi
  int v32; // eax
  __int64 result; // rax
  int v34; // [rsp+0h] [rbp-E8h]
  int v35; // [rsp+4h] [rbp-E4h]
  int v36; // [rsp+8h] [rbp-E0h]
  unsigned __int64 v37; // [rsp+Ch] [rbp-DCh]
  int v38; // [rsp+14h] [rbp-D4h]
  int v39; // [rsp+18h] [rbp-D0h]
  int v40; // [rsp+1Ch] [rbp-CCh]
  _DWORD v41[8]; // [rsp+20h] [rbp-C8h] BYREF
  __int64 v42; // [rsp+40h] [rbp-A8h]
  int v43; // [rsp+48h] [rbp-A0h]
  unsigned __int64 v44; // [rsp+4Ch] [rbp-9Ch]
  unsigned __int64 v45; // [rsp+54h] [rbp-94h]
  int v46; // [rsp+5Ch] [rbp-8Ch]
  _DWORD v47[2]; // [rsp+60h] [rbp-88h]
  unsigned __int64 v48; // [rsp+68h] [rbp-80h]
  int v49; // [rsp+70h] [rbp-78h]
  int v50; // [rsp+74h] [rbp-74h]
  int v51; // [rsp+78h] [rbp-70h]
  int v52; // [rsp+7Ch] [rbp-6Ch]
  int v53; // [rsp+80h] [rbp-68h]
  int v54; // [rsp+84h] [rbp-64h]
  int v55; // [rsp+88h] [rbp-60h]
  int v56; // [rsp+8Ch] [rbp-5Ch]
  int v57; // [rsp+90h] [rbp-58h]
  int v58; // [rsp+94h] [rbp-54h]
  int v59; // [rsp+98h] [rbp-50h]
  int v60; // [rsp+9Ch] [rbp-4Ch]

  v4 = 2036477234;
  v5 = 857760878;
  v6 = 1634760805;
  v7 = a1[1];
  v8 = a1[2];
  v9 = *a1;
  v10 = a1[3];
  v11 = *a1;
  v12 = *a2;
  v13 = a3;
  v38 = a2[1];
  v41[7] = v38;
  v41[0] = 1634760805;
  v14 = HIDWORD(v8);
  v41[5] = 857760878;
  v15 = HIDWORD(a3);
  v43 = 2036477234;
  v46 = 1797285236;
  v44 = v8;
  v41[6] = v12;
  v39 = v8;
  v40 = 10;
  *(_QWORD *)&v41[1] = v9;
  *(_QWORD *)&v41[3] = v7;
  v45 = v10;
  v42 = a3;
  v16 = v10;
  v17 = HIDWORD(v10);
  v37 = __PAIR64__(v7, HIDWORD(v9));
  v18 = HIDWORD(v7);
  v19 = 1797285236;
  do
  {
    v20 = v18 ^ __ROL4__(v14 + v6, 7);
    v21 = v15 ^ __ROL4__(v5 + v11, 7);
    v22 = __ROL4__(v20 + v6, 9) ^ v13;
    v34 = v14 ^ __ROL4__(v20 + v22, 13);
    v23 = v6 ^ __ROR4__(v22 + v34, 14);
    v35 = v16 ^ __ROL4__(v21 + v5, 9);
    v24 = v11 ^ __ROL4__(v21 + v35, 13);
    v25 = v5 ^ __ROR4__(v35 + v24, 14);
    v36 = v17 ^ __ROL4__(v12 + v4, 7);
    v26 = v37 ^ __ROL4__(v36 + v4, 9);
    v27 = v12 ^ __ROL4__(v36 + v26, 13);
    v28 = HIDWORD(v37) ^ __ROL4__(v39 + v19, 7);
    v29 = v38 ^ __ROL4__(v28 + v19, 9);
    v30 = v4 ^ __ROR4__(v26 + v27, 14);
    v31 = v39 ^ __ROL4__(v28 + v29, 13);
    v32 = v19 ^ __ROR4__(v29 + v31, 14);
    v11 = v24 ^ __ROL4__(v23 + v28, 7);
    LODWORD(v37) = v26 ^ __ROL4__(v23 + v11, 9);
    HIDWORD(v37) = v28 ^ __ROL4__(v11 + v37, 13);
    v12 = v27 ^ __ROL4__(v20 + v25, 7);
    v6 = v23 ^ __ROR4__(HIDWORD(v37) + v37, 14);
    v38 = v29 ^ __ROL4__(v25 + v12, 9);
    v18 = v20 ^ __ROL4__(v12 + v38, 13);
    v5 = v25 ^ __ROR4__(v38 + v18, 14);
    v39 = v31 ^ __ROL4__(v21 + v30, 7);
    v13 = __ROL4__(v30 + v39, 9) ^ v22;
    v15 = v21 ^ __ROL4__(v39 + v13, 13);
    v4 = v30 ^ __ROR4__(v13 + v15, 14);
    LODWORD(v14) = v34 ^ __ROL4__(v36 + v32, 7);
    v16 = v35 ^ __ROL4__(v32 + v14, 9);
    LODWORD(v17) = v36 ^ __ROL4__(v14 + v16, 13);
    v19 = v32 ^ __ROR4__(v16 + v17, 14);
    --v40;
  }
  while ( v40 != 0 );
  v47[1] = v11;
  v47[0] = v6;
  v48 = v37;
  v51 = v12;
  v49 = v18;
  v52 = v38;
  v50 = v5;
  v53 = v13;
  v54 = v15;
  v55 = v4;
  v58 = v16;
  v59 = v17;
  v60 = v19;
  v57 = v14;
  v56 = v39;
  for ( result = 0; result != 16; result += 4 )
    *(__m128i *)(a4 + result * 4) = _mm_add_epi32(
                                      _mm_loadu_si128((const __m128i *)&v41[result]),
                                      *(__m128i *)&v47[result]);
  return result * 4;
}
