__int64 __fastcall chacha20_block(unsigned __int64 *a1, int a2, int *a3, __int64 a4)
{
  unsigned int v4; // esi
  unsigned int v5; // r13d
  unsigned __int64 v6; // r11
  unsigned __int64 v7; // r10
  unsigned __int64 v8; // rbp
  int v9; // r14d
  int v10; // eax
  unsigned __int64 v11; // r9
  int v12; // ecx
  int v13; // edx
  unsigned int v14; // r12d
  unsigned int v15; // r8d
  unsigned int v16; // r15d
  unsigned int v17; // edi
  unsigned int v18; // r11d
  unsigned int v19; // r10d
  unsigned int v20; // ebx
  int v21; // r13d
  unsigned int v22; // esi
  unsigned int v23; // r10d
  int v24; // eax
  int v25; // ecx
  int v26; // r9d
  int v27; // r11d
  int v28; // edx
  int v29; // r12d
  int v30; // ebp
  int v31; // edi
  int v32; // r13d
  int v33; // esi
  int v34; // r8d
  int v35; // r10d
  int v36; // eax
  int v37; // ecx
  int v38; // r11d
  int v39; // ebp
  int v40; // edi
  int v41; // edx
  unsigned int v42; // ebx
  int v43; // r13d
  int v44; // r12d
  int v45; // r9d
  int v46; // r8d
  int v47; // r11d
  int v48; // esi
  int v49; // r15d
  int v50; // eax
  int v51; // ebx
  int v52; // r9d
  int v53; // r11d
  int v54; // r9d
  int v55; // r15d
  int v56; // r11d
  int v57; // r12d
  int v58; // r15d
  int v59; // edi
  int v60; // r8d
  int v61; // r10d
  int v62; // ebx
  int v63; // ecx
  int v64; // edx
  int v65; // r9d
  int v66; // r15d
  int v67; // r11d
  int v68; // ebp
  __int64 result; // rax
  int v70; // [rsp+0h] [rbp-D8h]
  int v71; // [rsp+4h] [rbp-D4h]
  unsigned int v72; // [rsp+8h] [rbp-D0h]
  int v73; // [rsp+Ch] [rbp-CCh]
  __m128i v74; // [rsp+10h] [rbp-C8h] BYREF
  unsigned __int64 v75; // [rsp+20h] [rbp-B8h]
  unsigned __int64 v76; // [rsp+28h] [rbp-B0h]
  unsigned __int64 v77; // [rsp+30h] [rbp-A8h]
  unsigned __int64 v78; // [rsp+38h] [rbp-A0h]
  int v79; // [rsp+40h] [rbp-98h]
  int v80; // [rsp+44h] [rbp-94h]
  int v81; // [rsp+48h] [rbp-90h]
  int v82; // [rsp+4Ch] [rbp-8Ch]
  __m128i v83; // [rsp+50h] [rbp-88h]
  unsigned __int64 v84; // [rsp+60h] [rbp-78h]
  unsigned __int64 v85; // [rsp+68h] [rbp-70h]
  unsigned __int64 v86; // [rsp+70h] [rbp-68h]
  unsigned __int64 v87; // [rsp+78h] [rbp-60h]
  int v88; // [rsp+80h] [rbp-58h]
  int v89; // [rsp+84h] [rbp-54h]
  int v90; // [rsp+88h] [rbp-50h]
  int v91; // [rsp+8Ch] [rbp-4Ch]

  v4 = 857760878;
  v5 = 1634760805;
  v6 = a1[1];
  v7 = a1[3];
  v8 = *a1;
  v9 = a3[2];
  v10 = a2;
  v11 = a1[2];
  v79 = a2;
  v12 = *a3;
  v13 = a3[1];
  v87 = v7;
  v75 = v8;
  v77 = v11;
  v14 = v7;
  v80 = v12;
  v81 = v13;
  v82 = v9;
  v73 = 10;
  v85 = v6;
  v15 = v6;
  v76 = v6;
  v16 = HIDWORD(v6);
  v84 = v8;
  v17 = HIDWORD(v8);
  v86 = v11;
  v18 = HIDWORD(v11);
  v78 = v7;
  v19 = 2036477234;
  v72 = HIDWORD(v7);
  v20 = 1797285236;
  v74 = _mm_loadu_si128((const __m128i *)&xmmword_14000FEF0);
  do
  {
    v21 = v8 + v5;
    v22 = v17 + v4;
    v23 = v15 + v19;
    v24 = __ROL4__(v21 ^ v10, 16);
    v25 = __ROL4__(v22 ^ v12, 16);
    v26 = v24 + v11;
    v27 = v25 + v18;
    v28 = __ROL4__(v23 ^ v13, 16);
    v29 = v28 + v14;
    v30 = __ROL4__(v26 ^ v8, 12);
    v31 = __ROL4__(v27 ^ v17, 12);
    v32 = v30 + v21;
    v33 = v31 + v22;
    v34 = __ROL4__(v29 ^ v15, 12);
    v35 = v34 + v23;
    v36 = __ROL4__(v32 ^ v24, 8);
    v37 = __ROL4__(v33 ^ v25, 8);
    v38 = v37 + v27;
    v70 = v36 + v26;
    v39 = __ROL4__((v36 + v26) ^ v30, 7);
    v40 = __ROL4__(v38 ^ v31, 7);
    v71 = v38;
    v41 = __ROL4__(v35 ^ v28, 8);
    v42 = v16 + v20;
    v43 = v40 + v32;
    v44 = v41 + v29;
    v45 = __ROL4__(v42 ^ v9, 16);
    v46 = __ROL4__(v44 ^ v34, 7);
    v47 = v72 + v45;
    v48 = v46 + v33;
    v49 = __ROL4__((v72 + v45) ^ v16, 12);
    v50 = __ROL4__(v48 ^ v36, 16);
    v51 = v49 + v42;
    v52 = __ROL4__(v51 ^ v45, 8);
    v53 = v52 + v47;
    v54 = __ROL4__(v43 ^ v52, 16);
    v55 = v53 ^ v49;
    v56 = v50 + v53;
    v57 = v54 + v44;
    v58 = __ROL4__(v55, 7);
    v59 = __ROL4__(v57 ^ v40, 12);
    v5 = v59 + v43;
    v9 = __ROL4__(v5 ^ v54, 8);
    v14 = v9 + v57;
    v17 = __ROL4__(v14 ^ v59, 7);
    v60 = __ROL4__(v56 ^ v46, 12);
    v61 = v58 + v35;
    v62 = v39 + v51;
    v4 = v60 + v48;
    v63 = __ROL4__(v61 ^ v37, 16);
    v64 = __ROL4__(v62 ^ v41, 16);
    v10 = __ROL4__(v4 ^ v50, 8);
    v65 = v63 + v70;
    v72 = v10 + v56;
    v66 = __ROL4__((v63 + v70) ^ v58, 12);
    v19 = v66 + v61;
    v15 = __ROL4__((v10 + v56) ^ v60, 7);
    v67 = v64 + v71;
    v12 = __ROL4__(v19 ^ v63, 8);
    v68 = __ROL4__((v64 + v71) ^ v39, 12);
    LODWORD(v11) = v12 + v65;
    v20 = v68 + v62;
    v16 = __ROL4__(v11 ^ v66, 7);
    v13 = __ROL4__(v20 ^ v64, 8);
    v18 = v13 + v67;
    LODWORD(v8) = __ROL4__(v18 ^ v68, 7);
    --v73;
  }
  while ( v73 != 0 );
  v88 = v10;
  v91 = v9;
  v87 = __PAIR64__(v72, v14);
  v85 = __PAIR64__(v16, v15);
  v89 = v12;
  v86 = __PAIR64__(v18, v11);
  v84 = __PAIR64__(v17, v8);
  v90 = v13;
  result = 0;
  v83 = _mm_unpacklo_epi64(
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v5), _mm_cvtsi32_si128(v4)),
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v19), _mm_cvtsi32_si128(v20)));
  do
  {
    *(__m128i *)(a4 + result) = _mm_add_epi32(
                                  _mm_loadu_si128((__m128i *)((char *)&v74 + result)),
                                  *(__m128i *)((char *)&v83 + result));
    result += 16;
  }
  while ( result != 64 );
  return result;
}
