__int64 __fastcall aes128_decrypt_block(const __m128i *a1, const __m128i *a2, __m128i *a3)
{
  const __m128i *v4; // rbx
  __m128i *v5; // r10
  int v6; // esi
  __m128i *v7; // rdi
  __int64 result; // rax
  __m128i v9; // xmm0
  __m128i *v10; // r11
  int v11; // edi
  int v12; // esi
  int v13; // r14d
  int v14; // r15d
  int v15; // ecx
  int v16; // eax
  unsigned __int8 v17; // r13
  int v18; // ebx
  unsigned __int8 v19; // r12
  int v20; // ebx
  int v21; // r13d
  int v22; // r15d
  unsigned __int8 v23; // r12
  unsigned __int8 v24; // bp
  char v25; // r14
  int v26; // ebx
  int v27; // r13d
  int v28; // r15d
  unsigned __int8 v29; // r12
  unsigned __int8 v30; // bp
  char v31; // r14
  int v32; // ebx
  int v33; // r13d
  int v34; // r15d
  unsigned __int8 v35; // r12
  unsigned __int8 v36; // bp
  __int8 v37; // r14
  int v38; // ebx
  int v39; // r15d
  unsigned __int8 v40; // r13
  int v41; // r14d
  unsigned __int8 v42; // r12
  int v43; // ebx
  int v44; // r13d
  int v45; // r15d
  unsigned __int8 v46; // r12
  unsigned __int8 v47; // bp
  char v48; // r14
  int v49; // ebx
  int v50; // r13d
  int v51; // r15d
  unsigned __int8 v52; // r12
  unsigned __int8 v53; // bp
  char v54; // r14
  int v55; // ebx
  int v56; // r13d
  int v57; // r15d
  unsigned __int8 v58; // r12
  unsigned __int8 v59; // bp
  __int8 v60; // r14
  int v61; // ebx
  int v62; // r15d
  unsigned __int8 v63; // r13
  int v64; // r14d
  unsigned __int8 v65; // r12
  int v66; // ebx
  int v67; // r13d
  int v68; // r15d
  unsigned __int8 v69; // r12
  unsigned __int8 v70; // bp
  char v71; // r14
  int v72; // ebx
  int v73; // r13d
  int v74; // r15d
  unsigned __int8 v75; // r12
  unsigned __int8 v76; // bp
  char v77; // r14
  int v78; // ebx
  int v79; // r13d
  int v80; // r15d
  unsigned __int8 v81; // r12
  unsigned __int8 v82; // bp
  int v83; // r13d
  unsigned __int8 v84; // r12
  int i; // r14d
  unsigned __int8 v86; // bl
  int v87; // r12d
  int v88; // r14d
  unsigned __int8 v89; // bl
  unsigned __int8 v90; // di
  char v91; // r14
  int v92; // ebx
  int v93; // r12d
  unsigned __int8 v94; // di
  unsigned __int8 v95; // si
  char v96; // r14
  int v97; // edi
  int v98; // ebx
  unsigned __int8 v99; // si
  unsigned __int8 v100; // cl
  const __m128i *v101; // [rsp+0h] [rbp-60h]
  __m128i v102; // [rsp+8h] [rbp-58h] BYREF
  __m128i v103; // [rsp+18h] [rbp-48h] BYREF
  char v104; // [rsp+28h] [rbp-38h] BYREF

  v4 = a1 + 9;
  v102 = _mm_xor_si128(_mm_loadu_si128(a2), _mm_loadu_si128(a1 + 10));
  while ( 1 )
  {
    v5 = &v103;
    v6 = 0;
    v7 = &v103;
    do
    {
      for ( result = 0; result != 4; ++result )
        v7->m128i_i8[result] = AES_INV_SBOX[v102.m128i_u8[(int)(result + 4 * (((_BYTE)v6 - (_BYTE)result) & 3))]];
      ++v6;
      v7 = (__m128i *)((char *)v7 + 4);
    }
    while ( v6 != 4 );
    v9 = _mm_xor_si128(_mm_loadu_si128(v4), v103);
    v103 = v9;
    if ( a1 == v4 )
      break;
    v101 = v4;
    v10 = &v102;
    do
    {
      v11 = v5->m128i_u8[0];
      v12 = v5->m128i_u8[1];
      v13 = 0;
      v14 = 4;
      v15 = v5->m128i_u8[2];
      v16 = v5->m128i_u8[3];
      v17 = 14;
      v18 = v11;
      do
      {
        v19 = v17;
        v17 >>= 1;
        v13 ^= v18 & -(v19 & 1);
        v18 = ((char)v18 >> 7) & 0x1B ^ (2 * v18);
        --v14;
      }
      while ( v14 != 0 );
      v20 = v5->m128i_u8[1];
      v21 = 4;
      v22 = 0;
      v23 = 11;
      do
      {
        v24 = v23;
        v23 >>= 1;
        v22 ^= v20 & -(v24 & 1);
        v20 = ((char)v20 >> 7) & 0x1B ^ (2 * v20);
        --v21;
      }
      while ( v21 != 0 );
      v25 = v22 ^ v13;
      v26 = v5->m128i_u8[2];
      v27 = 4;
      v28 = 0;
      v29 = 13;
      do
      {
        v30 = v29;
        v29 >>= 1;
        v28 ^= v26 & -(v30 & 1);
        v26 = ((char)v26 >> 7) & 0x1B ^ (2 * v26);
        --v27;
      }
      while ( v27 != 0 );
      v31 = v28 ^ v25;
      v32 = v5->m128i_u8[3];
      v33 = 4;
      v34 = 0;
      v35 = 9;
      do
      {
        v36 = v35;
        v35 >>= 1;
        v34 ^= v32 & -(v36 & 1);
        v32 = ((char)v32 >> 7) & 0x1B ^ (2 * v32);
        --v33;
      }
      while ( v33 != 0 );
      v37 = v34 ^ v31;
      v38 = v5->m128i_u8[0];
      v39 = 4;
      v40 = 9;
      v10->m128i_i8[0] = v37;
      v41 = 0;
      do
      {
        v42 = v40;
        v40 >>= 1;
        v41 ^= v38 & -(v42 & 1);
        v38 = ((char)v38 >> 7) & 0x1B ^ (2 * v38);
        --v39;
      }
      while ( v39 != 0 );
      v43 = v12;
      v44 = 4;
      v45 = 0;
      v46 = 14;
      do
      {
        v47 = v46;
        v46 >>= 1;
        v45 ^= v43 & -(v47 & 1);
        v43 = ((char)v43 >> 7) & 0x1B ^ (2 * v43);
        --v44;
      }
      while ( v44 != 0 );
      v48 = v45 ^ v41;
      v49 = v15;
      v50 = 4;
      v51 = 0;
      v52 = 11;
      do
      {
        v53 = v52;
        v52 >>= 1;
        v51 ^= v49 & -(v53 & 1);
        v49 = ((char)v49 >> 7) & 0x1B ^ (2 * v49);
        --v50;
      }
      while ( v50 != 0 );
      v54 = v51 ^ v48;
      v55 = v16;
      v56 = 4;
      v57 = 0;
      v58 = 13;
      do
      {
        v59 = v58;
        v58 >>= 1;
        v57 ^= v55 & -(v59 & 1);
        v55 = ((char)v55 >> 7) & 0x1B ^ (2 * v55);
        --v56;
      }
      while ( v56 != 0 );
      v60 = v57 ^ v54;
      v61 = v11;
      v62 = 4;
      v63 = 13;
      v10->m128i_i8[1] = v60;
      v64 = 0;
      do
      {
        v65 = v63;
        v63 >>= 1;
        v64 ^= v61 & -(v65 & 1);
        v61 = ((char)v61 >> 7) & 0x1B ^ (2 * v61);
        --v62;
      }
      while ( v62 != 0 );
      v66 = v12;
      v67 = 4;
      v68 = 0;
      v69 = 9;
      do
      {
        v70 = v69;
        v69 >>= 1;
        v68 ^= v66 & -(v70 & 1);
        v66 = ((char)v66 >> 7) & 0x1B ^ (2 * v66);
        --v67;
      }
      while ( v67 != 0 );
      v71 = v68 ^ v64;
      v72 = v15;
      v73 = 4;
      v74 = 0;
      v75 = 14;
      do
      {
        v76 = v75;
        v75 >>= 1;
        v74 ^= v72 & -(v76 & 1);
        v72 = ((char)v72 >> 7) & 0x1B ^ (2 * v72);
        --v73;
      }
      while ( v73 != 0 );
      v77 = v74 ^ v71;
      v78 = v16;
      v79 = 4;
      v80 = 0;
      v81 = 11;
      do
      {
        v82 = v81;
        v81 >>= 1;
        v80 ^= v78 & -(v82 & 1);
        v78 = ((char)v78 >> 7) & 0x1B ^ (2 * v78);
        --v79;
      }
      while ( v79 != 0 );
      v83 = 0;
      v84 = 11;
      v10->m128i_i8[2] = v80 ^ v77;
      for ( i = 4; i != 0; --i )
      {
        v86 = v84;
        v84 >>= 1;
        v83 ^= v11 & -(v86 & 1);
        v11 = ((char)v11 >> 7) & 0x1B ^ (2 * v11);
      }
      v87 = 4;
      v88 = 0;
      v89 = 13;
      do
      {
        v90 = v89;
        v89 >>= 1;
        v88 ^= v12 & -(v90 & 1);
        v12 = ((char)v12 >> 7) & 0x1B ^ (2 * v12);
        --v87;
      }
      while ( v87 != 0 );
      v91 = v83 ^ v88;
      v92 = 4;
      v93 = 0;
      v94 = 9;
      do
      {
        v95 = v94;
        v94 >>= 1;
        v93 ^= v15 & -(v95 & 1);
        v15 = ((char)v15 >> 7) & 0x1B ^ (2 * v15);
        --v92;
      }
      while ( v92 != 0 );
      v96 = v93 ^ v91;
      v97 = 4;
      v98 = 0;
      v99 = 14;
      do
      {
        v100 = v99;
        v99 >>= 1;
        v98 ^= v16 & -(v100 & 1);
        v16 = ((char)v16 >> 7) & 0x1B ^ (2 * v16);
        --v97;
      }
      while ( v97 != 0 );
      v5 = (__m128i *)((char *)v5 + 4);
      v10 = (__m128i *)((char *)v10 + 4);
      v10[-1].m128i_i8[15] = v98 ^ v96;
    }
    while ( v5 != (__m128i *)&v104 );
    v4 = v101 - 1;
  }
  *a3 = v9;
  return result;
}
