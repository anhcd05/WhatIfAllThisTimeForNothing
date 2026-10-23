// chacha20_block = sub_3A10 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_3A10(const __m128i *a1, int a2, int *a3, __int64 a4)
{
  int v4; // eax
  unsigned int v5; // r10d
  unsigned int v6; // r11d
  unsigned int v7; // r13d
  __m128i v8; // xmm1
  int v9; // r14d
  int v10; // ecx
  int v11; // edx
  int v12; // ebp
  __int32 v13; // ebx
  __int32 v14; // r9d
  int v15; // edi
  __int32 v16; // esi
  __int32 v17; // r12d
  __int32 v18; // r15d
  unsigned int v19; // r8d
  unsigned int v20; // r13d
  unsigned __int32 v21; // r11d
  unsigned __int32 v22; // r8d
  int v23; // eax
  int v24; // ecx
  int v25; // edi
  int v26; // r9d
  int v27; // edx
  int v28; // r12d
  int v29; // ebp
  int v30; // ebx
  int v31; // r13d
  int v32; // r11d
  int v33; // esi
  int v34; // r8d
  int v35; // eax
  int v36; // ecx
  int v37; // r9d
  int v38; // ebp
  int v39; // ebx
  int v40; // edx
  unsigned __int32 v41; // r10d
  int v42; // r13d
  int v43; // r12d
  int v44; // edi
  int v45; // esi
  int v46; // r9d
  int v47; // r11d
  int v48; // r15d
  int v49; // eax
  int v50; // r10d
  int v51; // edi
  int v52; // r9d
  int v53; // edi
  int v54; // r15d
  int v55; // r9d
  int v56; // r12d
  int v57; // r15d
  int v58; // ebx
  int v59; // esi
  int v60; // r8d
  int v61; // r10d
  int v62; // ecx
  int v63; // edx
  int v64; // r9d
  int v65; // edi
  int v66; // ebp
  int v67; // r15d
  __int64 result; // rax
  int v69; // [rsp+0h] [rbp-D0h]
  int v70; // [rsp+4h] [rbp-CCh]
  __int32 v71; // [rsp+8h] [rbp-C8h]
  int v72; // [rsp+Ch] [rbp-C4h]
  _QWORD v74[6]; // [rsp+18h] [rbp-B8h] BYREF
  int v75; // [rsp+48h] [rbp-88h]
  int v76; // [rsp+4Ch] [rbp-84h]
  int v77; // [rsp+50h] [rbp-80h]
  int v78; // [rsp+54h] [rbp-7Ch]
  __m128i v79; // [rsp+58h] [rbp-78h]
  __m128i v80; // [rsp+68h] [rbp-68h]
  __m128i v81; // [rsp+78h] [rbp-58h]
  int v82; // [rsp+88h] [rbp-48h]
  int v83; // [rsp+8Ch] [rbp-44h]
  int v84; // [rsp+90h] [rbp-40h]
  int v85; // [rsp+94h] [rbp-3Ch]

  v4 = a2;
  v5 = 1797285236;
  v6 = 857760878;
  v7 = 1634760805;
  v8 = _mm_loadu_si128(a1);
  v9 = a3[2];
  v10 = *a3;
  *(__m128i *)v74 = _mm_load_si128((const __m128i *)&xmmword_6ED0);
  v11 = a3[1];
  v12 = _mm_cvtsi128_si32(v8);
  v80 = v8;
  v13 = v8.m128i_i32[1];
  v75 = a2;
  v81 = _mm_loadu_si128(a1 + 1);
  v14 = v81.m128i_i32[1];
  v15 = _mm_cvtsi128_si32(v81);
  v76 = v10;
  v77 = v11;
  v78 = v9;
  *(__m128i *)&v74[2] = v8;
  *(__m128i *)&v74[4] = v81;
  v16 = v8.m128i_i32[2];
  v72 = 10;
  v17 = v81.m128i_i32[2];
  v18 = v8.m128i_i32[3];
  v71 = v81.m128i_i32[3];
  v19 = 2036477234;
  do
  {
    v20 = v12 + v7;
    v21 = v13 + v6;
    v22 = v16 + v19;
    v23 = __ROL4__(v20 ^ v4, 16);
    v24 = __ROL4__(v21 ^ v10, 16);
    v25 = v23 + v15;
    v26 = v24 + v14;
    v27 = __ROL4__(v22 ^ v11, 16);
    v28 = v27 + v17;
    v29 = __ROL4__(v25 ^ v12, 12);
    v30 = __ROL4__(v26 ^ v13, 12);
    v31 = v29 + v20;
    v32 = v30 + v21;
    v33 = __ROL4__(v28 ^ v16, 12);
    v34 = v33 + v22;
    v35 = __ROL4__(v31 ^ v23, 8);
    v36 = __ROL4__(v32 ^ v24, 8);
    v37 = v36 + v26;
    v69 = v35 + v25;
    v38 = __ROL4__((v35 + v25) ^ v29, 7);
    v39 = __ROL4__(v37 ^ v30, 7);
    v70 = v37;
    v40 = __ROL4__(v34 ^ v27, 8);
    v41 = v18 + v5;
    v42 = v39 + v31;
    v43 = v40 + v28;
    v44 = __ROL4__(v41 ^ v9, 16);
    v45 = __ROL4__(v43 ^ v33, 7);
    v46 = v71 + v44;
    v47 = v45 + v32;
    v48 = __ROL4__((v71 + v44) ^ v18, 12);
    v49 = __ROL4__(v47 ^ v35, 16);
    v50 = v48 + v41;
    v51 = __ROL4__(v50 ^ v44, 8);
    v52 = v51 + v46;
    v53 = __ROL4__(v42 ^ v51, 16);
    v54 = v52 ^ v48;
    v55 = v49 + v52;
    v56 = v53 + v43;
    v57 = __ROL4__(v54, 7);
    v58 = __ROL4__(v56 ^ v39, 12);
    v7 = v58 + v42;
    v9 = __ROL4__(v7 ^ v53, 8);
    v17 = v9 + v56;
    v13 = __ROL4__(v17 ^ v58, 7);
    v59 = __ROL4__(v55 ^ v45, 12);
    v60 = v57 + v34;
    v61 = v38 + v50;
    v6 = v59 + v47;
    v62 = __ROL4__(v60 ^ v36, 16);
    v63 = __ROL4__(v61 ^ v40, 16);
    v4 = __ROL4__(v6 ^ v49, 8);
    v71 = v55 + v4;
    v64 = v63 + v70;
    v16 = __ROL4__(v71 ^ v59, 7);
    v65 = v62 + v69;
    v66 = __ROL4__((v63 + v70) ^ v38, 12);
    v67 = __ROL4__((v62 + v69) ^ v57, 12);
    v5 = v66 + v61;
    v19 = v67 + v60;
    v11 = __ROL4__(v5 ^ v63, 8);
    v10 = __ROL4__(v19 ^ v62, 8);
    v14 = v11 + v64;
    v15 = v10 + v65;
    v12 = __ROL4__(v14 ^ v66, 7);
    v18 = __ROL4__(v15 ^ v67, 7);
    --v72;
  }
  while ( v72 != 0 );
  v82 = v4;
  v85 = v9;
  *(__int64 *)((char *)v80.m128i_i64 + 4) = __PAIR64__(v16, v13);
  v83 = v10;
  v81.m128i_i32[0] = v15;
  v80.m128i_i32[3] = v18;
  *(__int64 *)((char *)v81.m128i_i64 + 4) = __PAIR64__(v17, v14);
  v80.m128i_i32[0] = v12;
  v84 = v11;
  v81.m128i_i32[3] = v71;
  result = 0;
  v79 = _mm_unpacklo_epi64(
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v7), _mm_cvtsi32_si128(v6)),
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v19), _mm_cvtsi32_si128(v5)));
  do
  {
    *(__m128i *)(a4 + result * 8) = _mm_add_epi32(
                                      _mm_load_si128((const __m128i *)&v74[result]),
                                      *(__m128i *)((char *)&v79 + result * 8));
    result += 2;
  }
  while ( result != 8 );
  return result * 8;
}
