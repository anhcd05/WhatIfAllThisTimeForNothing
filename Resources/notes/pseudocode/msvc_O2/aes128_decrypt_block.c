void __fastcall aes128_decrypt_block(const __m128i *rk, const __m128i *in, unsigned __int8 *out)
{
  __int64 v3; // r10
  const unsigned __int8 *v4; // r9
  int v5; // edx
  __int64 i; // r8
  __int64 v7; // rax
  __int64 v8; // r12
  unsigned __int8 v9; // r11
  unsigned __int8 v10; // r10
  unsigned __int8 v11; // di
  unsigned __int8 v12; // r9
  unsigned __int8 v13; // si
  char v14; // r13
  unsigned __int8 v15; // r15
  unsigned __int8 v16; // r8
  char v17; // cl
  unsigned __int8 v18; // r10
  unsigned __int8 v19; // r9
  char v20; // r12
  unsigned __int8 v21; // r8
  char v22; // cl
  unsigned __int8 v23; // r10
  unsigned __int8 v24; // r9
  char v25; // r14
  unsigned __int8 v26; // r8
  char v27; // cl
  unsigned __int8 v28; // bl
  unsigned __int8 v29; // r9
  char v30; // r10
  unsigned __int8 v31; // r8
  char v32; // cl
  unsigned __int8 v33; // r9
  unsigned __int8 v34; // r10
  char v35; // r13
  unsigned __int8 v36; // r10
  unsigned __int8 v37; // r8
  char v38; // cl
  unsigned __int8 v39; // r10
  unsigned __int8 v40; // r9
  char v41; // r12
  unsigned __int8 v42; // r8
  char v43; // cl
  unsigned __int8 v44; // r10
  unsigned __int8 v45; // r9
  char v46; // r14
  unsigned __int8 v47; // r8
  char v48; // cl
  unsigned __int8 v49; // bl
  unsigned __int8 v50; // r9
  char v51; // r10
  unsigned __int8 v52; // r8
  char v53; // cl
  unsigned __int8 v54; // r9
  unsigned __int8 v55; // r10
  char v56; // r13
  unsigned __int8 v57; // r10
  unsigned __int8 v58; // r8
  char v59; // cl
  unsigned __int8 v60; // r10
  unsigned __int8 v61; // r9
  char v62; // r12
  unsigned __int8 v63; // r8
  char v64; // cl
  unsigned __int8 v65; // r10
  unsigned __int8 v66; // r9
  char v67; // r14
  unsigned __int8 v68; // r8
  char v69; // cl
  unsigned __int8 v70; // bl
  unsigned __int8 v71; // r9
  char v72; // r10
  unsigned __int8 v73; // r8
  char v74; // cl
  unsigned __int8 v75; // r9
  char v76; // r10
  char v77; // r14
  unsigned __int8 v78; // r8
  char v79; // cl
  unsigned __int8 v80; // r9
  char v81; // bl
  unsigned __int8 v82; // r8
  char v83; // cl
  unsigned __int8 v84; // r9
  char v85; // r11
  unsigned __int8 v86; // r8
  char v87; // cl
  unsigned __int8 v88; // r10
  char v89; // al
  unsigned __int8 v90; // r9
  char v91; // dl
  __int64 v92; // [rsp+0h] [rbp-50h]
  __int64 v93; // [rsp+8h] [rbp-48h]
  const unsigned __int8 *v94; // [rsp+10h] [rbp-40h]
  unsigned __int8 t[16]; // [rsp+20h] [rbp-30h]
  unsigned __int8 s[16]; // [rsp+30h] [rbp-20h]

  v3 = 9;
  v4 = &rk[9].m128i_u8[2];
  v93 = 9;
  v94 = &rk[9].m128i_u8[2];
  *(__m128i *)s = _mm_xor_si128(_mm_loadu_si128(rk + 10), _mm_loadu_si128(in));
  do
  {
    v5 = 0;
    for ( i = 0; i < 4; ++i )
    {
      t[4 * i] = AES_INV_SBOX[s[4 * (v5 & 3)]];
      t[4 * i + 1] = AES_INV_SBOX[s[4 * (((_BYTE)v5 - 1) & 3) + 1]];
      v7 = 4 * (((_BYTE)v5++ - 2) & 3u);
      t[4 * i + 2] = AES_INV_SBOX[s[v7 + 2]];
      t[4 * i + 3] = AES_INV_SBOX[s[4 * (v5 & 3) + 3]];
    }
    t[0] ^= *(v4 - 2);
    t[1] ^= *(v4 - 1);
    t[2] ^= *v4;
    t[3] ^= v4[1];
    t[4] ^= v4[2];
    t[5] ^= v4[3];
    t[6] ^= v4[4];
    t[7] ^= v4[5];
    t[8] ^= v4[6];
    t[9] ^= v4[7];
    t[10] ^= v4[8];
    t[11] ^= v4[9];
    t[12] ^= v4[10];
    t[13] ^= v4[11];
    t[14] ^= v4[12];
    t[15] ^= v4[13];
    if ( v3 <= 0 )
    {
      *(_OWORD *)s = *(_OWORD *)t;
    }
    else
    {
      v8 = 0;
      v92 = 0;
      do
      {
        v9 = t[v8];
        v10 = 14;
        v11 = t[v8 + 1];
        v12 = v9;
        v13 = t[v8 + 2];
        v14 = 0;
        v15 = t[v8 + 3];
        do
        {
          v16 = v10;
          v17 = v12 ^ v14;
          if ( (v10 & 1) == 0 )
            v17 = v14;
          v14 = v17;
          v10 >>= 1;
          v12 = (27 * (v12 >> 7)) ^ (2 * v12);
        }
        while ( v16 >= 2u );
        v18 = 11;
        v19 = t[v8 + 1];
        v20 = 0;
        do
        {
          v21 = v18;
          v22 = v19 ^ v20;
          if ( (v18 & 1) == 0 )
            v22 = v20;
          v20 = v22;
          v18 >>= 1;
          v19 = (27 * (v19 >> 7)) ^ (2 * v19);
        }
        while ( v21 >= 2u );
        v23 = 13;
        v24 = v13;
        v25 = 0;
        do
        {
          v26 = v23;
          v27 = v24 ^ v25;
          if ( (v23 & 1) == 0 )
            v27 = v25;
          v25 = v27;
          v23 >>= 1;
          v24 = (27 * (v24 >> 7)) ^ (2 * v24);
        }
        while ( v26 >= 2u );
        v28 = 9;
        v29 = v15;
        v30 = 0;
        do
        {
          v31 = v28;
          v32 = v29 ^ v30;
          if ( (v28 & 1) == 0 )
            v32 = v30;
          v30 = v32;
          v28 >>= 1;
          v29 = (27 * (v29 >> 7)) ^ (2 * v29);
        }
        while ( v31 >= 2u );
        v33 = v9;
        v34 = v14 ^ v20 ^ v25 ^ v32;
        v35 = 0;
        s[v92] = v34;
        v36 = 9;
        do
        {
          v37 = v36;
          v38 = v33 ^ v35;
          if ( (v36 & 1) == 0 )
            v38 = v35;
          v35 = v38;
          v36 >>= 1;
          v33 = (27 * (v33 >> 7)) ^ (2 * v33);
        }
        while ( v37 >= 2u );
        v39 = 14;
        v40 = v11;
        v41 = 0;
        do
        {
          v42 = v39;
          v43 = v40 ^ v41;
          if ( (v39 & 1) == 0 )
            v43 = v41;
          v41 = v43;
          v39 >>= 1;
          v40 = (27 * (v40 >> 7)) ^ (2 * v40);
        }
        while ( v42 >= 2u );
        v44 = 11;
        v45 = v13;
        v46 = 0;
        do
        {
          v47 = v44;
          v48 = v45 ^ v46;
          if ( (v44 & 1) == 0 )
            v48 = v46;
          v46 = v48;
          v44 >>= 1;
          v45 = (27 * (v45 >> 7)) ^ (2 * v45);
        }
        while ( v47 >= 2u );
        v49 = 13;
        v50 = v15;
        v51 = 0;
        do
        {
          v52 = v49;
          v53 = v50 ^ v51;
          if ( (v49 & 1) == 0 )
            v53 = v51;
          v51 = v53;
          v49 >>= 1;
          v50 = (27 * (v50 >> 7)) ^ (2 * v50);
        }
        while ( v52 >= 2u );
        v54 = v9;
        v55 = v35 ^ v41 ^ v46 ^ v53;
        v56 = 0;
        s[v92 + 1] = v55;
        v57 = 13;
        do
        {
          v58 = v57;
          v59 = v54 ^ v56;
          if ( (v57 & 1) == 0 )
            v59 = v56;
          v56 = v59;
          v57 >>= 1;
          v54 = (27 * (v54 >> 7)) ^ (2 * v54);
        }
        while ( v58 >= 2u );
        v60 = 9;
        v61 = v11;
        v62 = 0;
        do
        {
          v63 = v60;
          v64 = v61 ^ v62;
          if ( (v60 & 1) == 0 )
            v64 = v62;
          v62 = v64;
          v60 >>= 1;
          v61 = (27 * (v61 >> 7)) ^ (2 * v61);
        }
        while ( v63 >= 2u );
        v65 = 14;
        v66 = v13;
        v67 = 0;
        do
        {
          v68 = v65;
          v69 = v66 ^ v67;
          if ( (v65 & 1) == 0 )
            v69 = v67;
          v67 = v69;
          v65 >>= 1;
          v66 = (27 * (v66 >> 7)) ^ (2 * v66);
        }
        while ( v68 >= 2u );
        v70 = 11;
        v71 = v15;
        v72 = 0;
        do
        {
          v73 = v70;
          v74 = v71 ^ v72;
          if ( (v70 & 1) == 0 )
            v74 = v72;
          v72 = v74;
          v70 >>= 1;
          v71 = (27 * (v71 >> 7)) ^ (2 * v71);
        }
        while ( v73 >= 2u );
        v75 = 11;
        v76 = v62 ^ v67 ^ v74;
        v77 = 0;
        s[v92 + 2] = v56 ^ v76;
        do
        {
          v78 = v75;
          v79 = v9 ^ v77;
          if ( (v75 & 1) == 0 )
            v79 = v77;
          v77 = v79;
          v75 >>= 1;
          v9 = (27 * (v9 >> 7)) ^ (2 * v9);
        }
        while ( v78 >= 2u );
        v80 = 13;
        v81 = 0;
        do
        {
          v82 = v80;
          v83 = v11 ^ v81;
          if ( (v80 & 1) == 0 )
            v83 = v81;
          v81 = v83;
          v80 >>= 1;
          v11 = (27 * (v11 >> 7)) ^ (2 * v11);
        }
        while ( v82 >= 2u );
        v84 = 9;
        v85 = 0;
        do
        {
          v86 = v84;
          v87 = v13 ^ v85;
          if ( (v84 & 1) == 0 )
            v87 = v85;
          v85 = v87;
          v84 >>= 1;
          v13 = (27 * (v13 >> 7)) ^ (2 * v13);
        }
        while ( v86 >= 2u );
        v88 = 14;
        v89 = 0;
        do
        {
          v90 = v88;
          v91 = v15 ^ v89;
          if ( (v88 & 1) == 0 )
            v91 = v89;
          v89 = v91;
          v88 >>= 1;
          v15 = (27 * (v15 >> 7)) ^ (2 * v15);
        }
        while ( v90 >= 2u );
        s[v92 + 3] = v77 ^ v81 ^ v87 ^ v91;
        v8 = v92 + 4;
        v92 = v8;
      }
      while ( v8 < 16 );
      v4 = v94;
      v3 = v93;
    }
    --v3;
    v4 -= 16;
    v93 = v3;
    v94 = v4;
  }
  while ( v3 >= 0 );
  *(_OWORD *)out = *(_OWORD *)s;
}
