// aes128_decrypt_block = sub_140002B90 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002B90(const __m128i *a1, const __m128i *a2, __m128i *a3)
{
  const __m128i *v4; // rdi
  __m128i *v6; // rbx
  int v7; // ecx
  __m128i *v8; // r8
  __int64 result; // rax
  __m128i v10; // xmm0
  __m128i *v11; // rsi
  int v12; // r8d
  int v13; // ecx
  int v14; // r15d
  int v15; // r14d
  int v16; // edx
  int v17; // eax
  unsigned __int8 v18; // r13
  int v19; // edi
  unsigned __int8 v20; // r12
  int v21; // edi
  int v22; // r13d
  int v23; // r15d
  unsigned __int8 v24; // r12
  unsigned __int8 v25; // bp
  char v26; // r14
  int v27; // edi
  int v28; // r13d
  int v29; // r15d
  unsigned __int8 v30; // r12
  unsigned __int8 v31; // bp
  char v32; // r14
  int v33; // edi
  int v34; // r13d
  int v35; // r15d
  unsigned __int8 v36; // r12
  unsigned __int8 v37; // bp
  __int8 v38; // r14
  int v39; // edi
  int v40; // r15d
  unsigned __int8 v41; // r13
  int v42; // r14d
  unsigned __int8 v43; // r12
  int v44; // edi
  int v45; // r13d
  int v46; // r15d
  unsigned __int8 v47; // r12
  unsigned __int8 v48; // bp
  char v49; // r14
  int v50; // edi
  int v51; // r13d
  int v52; // r15d
  unsigned __int8 v53; // r12
  unsigned __int8 v54; // bp
  char v55; // r14
  int v56; // edi
  int v57; // r13d
  int v58; // r15d
  unsigned __int8 v59; // r12
  unsigned __int8 v60; // bp
  __int8 v61; // r14
  int v62; // edi
  int v63; // r15d
  unsigned __int8 v64; // r13
  int v65; // r14d
  unsigned __int8 v66; // r12
  int v67; // edi
  int v68; // r13d
  int v69; // r15d
  unsigned __int8 v70; // r12
  unsigned __int8 v71; // bp
  char v72; // r14
  int v73; // edi
  int v74; // r13d
  int v75; // r15d
  unsigned __int8 v76; // r12
  unsigned __int8 v77; // bp
  char v78; // r14
  int v79; // edi
  int v80; // r13d
  int v81; // r15d
  unsigned __int8 v82; // r12
  unsigned __int8 v83; // bp
  int v84; // r13d
  unsigned __int8 v85; // r12
  int i; // r14d
  unsigned __int8 v87; // di
  int v88; // r12d
  int v89; // r14d
  unsigned __int8 v90; // di
  unsigned __int8 v91; // r8
  char v92; // r14
  int v93; // edi
  int v94; // r12d
  unsigned __int8 v95; // r8
  unsigned __int8 v96; // cl
  char v97; // r14
  int v98; // r8d
  int v99; // edi
  unsigned __int8 v100; // cl
  unsigned __int8 v101; // dl
  const __m128i *v102; // [rsp+8h] [rbp-70h]
  __m128i v103; // [rsp+10h] [rbp-68h] BYREF
  __m128i v104; // [rsp+20h] [rbp-58h] BYREF
  char v105; // [rsp+30h] [rbp-48h] BYREF

  v4 = a1 + 9;
  v103 = _mm_xor_si128(_mm_loadu_si128(a2), _mm_loadu_si128(a1 + 10));
  while ( 1 )
  {
    v6 = &v104;
    v7 = 0;
    v8 = &v104;
    do
    {
      for ( result = 0; result != 4; ++result )
        v8->m128i_i8[result] = byte_14000FCE0[v103.m128i_u8[(int)(result + 4 * (((_BYTE)v7 - (_BYTE)result) & 3))]];
      ++v7;
      v8 = (__m128i *)((char *)v8 + 4);
    }
    while ( v7 != 4 );
    v10 = _mm_xor_si128(_mm_loadu_si128(v4), v104);
    v104 = v10;
    if ( a1 == v4 )
      break;
    v102 = v4;
    v11 = &v103;
    do
    {
      v12 = v6->m128i_u8[0];
      v13 = v6->m128i_u8[1];
      v14 = 4;
      v15 = 0;
      v16 = v6->m128i_u8[2];
      v17 = v6->m128i_u8[3];
      v18 = 14;
      v19 = v12;
      do
      {
        v20 = v18;
        v18 >>= 1;
        v15 ^= v19 & -(v20 & 1);
        v19 = ((char)v19 >> 7) & 0x1B ^ (2 * v19);
        --v14;
      }
      while ( v14 != 0 );
      v21 = v6->m128i_u8[1];
      v22 = 4;
      v23 = 0;
      v24 = 11;
      do
      {
        v25 = v24;
        v24 >>= 1;
        v23 ^= v21 & -(v25 & 1);
        v21 = ((char)v21 >> 7) & 0x1B ^ (2 * v21);
        --v22;
      }
      while ( v22 != 0 );
      v26 = v23 ^ v15;
      v27 = v6->m128i_u8[2];
      v28 = 4;
      v29 = 0;
      v30 = 13;
      do
      {
        v31 = v30;
        v30 >>= 1;
        v29 ^= v27 & -(v31 & 1);
        v27 = ((char)v27 >> 7) & 0x1B ^ (2 * v27);
        --v28;
      }
      while ( v28 != 0 );
      v32 = v29 ^ v26;
      v33 = v6->m128i_u8[3];
      v34 = 4;
      v35 = 0;
      v36 = 9;
      do
      {
        v37 = v36;
        v36 >>= 1;
        v35 ^= v33 & -(v37 & 1);
        v33 = ((char)v33 >> 7) & 0x1B ^ (2 * v33);
        --v34;
      }
      while ( v34 != 0 );
      v38 = v35 ^ v32;
      v39 = v6->m128i_u8[0];
      v40 = 4;
      v41 = 9;
      v11->m128i_i8[0] = v38;
      v42 = 0;
      do
      {
        v43 = v41;
        v41 >>= 1;
        v42 ^= v39 & -(v43 & 1);
        v39 = ((char)v39 >> 7) & 0x1B ^ (2 * v39);
        --v40;
      }
      while ( v40 != 0 );
      v44 = v13;
      v45 = 4;
      v46 = 0;
      v47 = 14;
      do
      {
        v48 = v47;
        v47 >>= 1;
        v46 ^= v44 & -(v48 & 1);
        v44 = ((char)v44 >> 7) & 0x1B ^ (2 * v44);
        --v45;
      }
      while ( v45 != 0 );
      v49 = v46 ^ v42;
      v50 = v16;
      v51 = 4;
      v52 = 0;
      v53 = 11;
      do
      {
        v54 = v53;
        v53 >>= 1;
        v52 ^= v50 & -(v54 & 1);
        v50 = ((char)v50 >> 7) & 0x1B ^ (2 * v50);
        --v51;
      }
      while ( v51 != 0 );
      v55 = v52 ^ v49;
      v56 = v17;
      v57 = 4;
      v58 = 0;
      v59 = 13;
      do
      {
        v60 = v59;
        v59 >>= 1;
        v58 ^= v56 & -(v60 & 1);
        v56 = ((char)v56 >> 7) & 0x1B ^ (2 * v56);
        --v57;
      }
      while ( v57 != 0 );
      v61 = v58 ^ v55;
      v62 = v12;
      v63 = 4;
      v64 = 13;
      v11->m128i_i8[1] = v61;
      v65 = 0;
      do
      {
        v66 = v64;
        v64 >>= 1;
        v65 ^= v62 & -(v66 & 1);
        v62 = ((char)v62 >> 7) & 0x1B ^ (2 * v62);
        --v63;
      }
      while ( v63 != 0 );
      v67 = v13;
      v68 = 4;
      v69 = 0;
      v70 = 9;
      do
      {
        v71 = v70;
        v70 >>= 1;
        v69 ^= v67 & -(v71 & 1);
        v67 = ((char)v67 >> 7) & 0x1B ^ (2 * v67);
        --v68;
      }
      while ( v68 != 0 );
      v72 = v69 ^ v65;
      v73 = v16;
      v74 = 4;
      v75 = 0;
      v76 = 14;
      do
      {
        v77 = v76;
        v76 >>= 1;
        v75 ^= v73 & -(v77 & 1);
        v73 = ((char)v73 >> 7) & 0x1B ^ (2 * v73);
        --v74;
      }
      while ( v74 != 0 );
      v78 = v75 ^ v72;
      v79 = v17;
      v80 = 4;
      v81 = 0;
      v82 = 11;
      do
      {
        v83 = v82;
        v82 >>= 1;
        v81 ^= v79 & -(v83 & 1);
        v79 = ((char)v79 >> 7) & 0x1B ^ (2 * v79);
        --v80;
      }
      while ( v80 != 0 );
      v84 = 0;
      v85 = 11;
      v11->m128i_i8[2] = v81 ^ v78;
      for ( i = 4; i != 0; --i )
      {
        v87 = v85;
        v85 >>= 1;
        v84 ^= v12 & -(v87 & 1);
        v12 = ((char)v12 >> 7) & 0x1B ^ (2 * v12);
      }
      v88 = 4;
      v89 = 0;
      v90 = 13;
      do
      {
        v91 = v90;
        v90 >>= 1;
        v89 ^= v13 & -(v91 & 1);
        v13 = ((char)v13 >> 7) & 0x1B ^ (2 * v13);
        --v88;
      }
      while ( v88 != 0 );
      v92 = v84 ^ v89;
      v93 = 4;
      v94 = 0;
      v95 = 9;
      do
      {
        v96 = v95;
        v95 >>= 1;
        v94 ^= v16 & -(v96 & 1);
        v16 = ((char)v16 >> 7) & 0x1B ^ (2 * v16);
        --v93;
      }
      while ( v93 != 0 );
      v97 = v94 ^ v92;
      v98 = 4;
      v99 = 0;
      v100 = 14;
      do
      {
        v101 = v100;
        v100 >>= 1;
        v99 ^= v17 & -(v101 & 1);
        v17 = ((char)v17 >> 7) & 0x1B ^ (2 * v17);
        --v98;
      }
      while ( v98 != 0 );
      v6 = (__m128i *)((char *)v6 + 4);
      v11 = (__m128i *)((char *)v11 + 4);
      v11[-1].m128i_i8[15] = v99 ^ v97;
    }
    while ( v6 != (__m128i *)&v105 );
    v4 = v102 - 1;
  }
  *a3 = v10;
  return result;
}
