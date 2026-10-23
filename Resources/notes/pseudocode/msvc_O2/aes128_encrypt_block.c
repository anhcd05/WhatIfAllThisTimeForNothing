void __fastcall aes128_encrypt_block(const __m128i *rk, const __m128i *in, unsigned __int8 *out)
{
  __int64 v3; // r9
  const unsigned __int8 *v4; // rdi
  __int64 v5; // r8
  int v6; // eax
  __int64 v7; // rcx
  char v8; // cl
  char v9; // r10
  char v10; // dl
  unsigned __int8 v11; // r15
  unsigned __int8 v12; // r12
  char v13; // cl
  char v14; // si
  char v15; // r13
  char v16; // cl
  unsigned __int8 v17; // si
  unsigned __int8 v18; // r13
  char v19; // r11
  char v20; // dl
  char v21; // cl
  char v22; // cl
  char v23; // r9
  char v24; // dl
  char v25; // cl
  unsigned __int8 v26; // bl
  char v27; // cl
  char v28; // r9
  char v29; // dl
  char v30; // cl
  char v31; // al
  unsigned __int8 v32; // dl
  char v33; // r14
  unsigned __int8 v34; // cl
  char v35; // r14
  unsigned __int8 v36; // r9
  unsigned __int8 v37; // r8
  unsigned __int8 v38; // r11
  unsigned __int8 v39; // r14
  unsigned __int8 v40; // r10
  unsigned __int8 v41; // al
  unsigned __int8 v42; // r9
  unsigned __int8 v43; // r10
  unsigned __int8 v44; // r15
  unsigned __int8 v45; // r12
  unsigned __int8 v46; // r13
  unsigned __int8 v47; // si
  unsigned __int8 v48; // cl
  unsigned __int8 v49; // dl
  unsigned __int8 v50; // r8
  unsigned __int8 v51; // r11
  unsigned __int8 v52; // bl
  unsigned __int8 v53; // r14
  unsigned __int8 v54; // al
  unsigned __int8 v55; // [rsp+0h] [rbp-50h]
  unsigned __int8 v56; // [rsp+1h] [rbp-4Fh]
  unsigned __int8 v57; // [rsp+2h] [rbp-4Eh]
  unsigned __int8 v58; // [rsp+3h] [rbp-4Dh]
  unsigned __int8 v59; // [rsp+4h] [rbp-4Ch]
  unsigned __int8 v60; // [rsp+5h] [rbp-4Bh]
  unsigned __int8 v61; // [rsp+6h] [rbp-4Ah]
  unsigned __int8 v62; // [rsp+7h] [rbp-49h]
  unsigned __int8 v63; // [rsp+8h] [rbp-48h]
  unsigned __int8 v64; // [rsp+9h] [rbp-47h]
  __int64 v65; // [rsp+10h] [rbp-40h]
  unsigned __int8 s[16]; // [rsp+20h] [rbp-30h]
  unsigned __int8 t[16]; // [rsp+38h] [rbp-18h]

  v3 = 1;
  v65 = 1;
  v4 = &rk[1].m128i_u8[2];
  *(__m128i *)s = _mm_xor_si128(_mm_loadu_si128(rk), _mm_loadu_si128(in));
  do
  {
    v5 = 0;
    v6 = 2;
    do
    {
      t[4 * v5] = AES_SBOX[s[4 * (((_BYTE)v6 - 2) & 3)]];
      t[4 * v5 + 1] = AES_SBOX[s[4 * (((_BYTE)v6 - 1) & 3) + 1]];
      v7 = 4 * (v6++ & 3u);
      t[4 * v5 + 2] = AES_SBOX[s[v7 + 2]];
      t[4 * v5++ + 3] = AES_SBOX[s[4 * (v6 & 3) + 3]];
    }
    while ( v5 < 4 );
    if ( v3 >= 10 )
    {
      *(_OWORD *)s = *(_OWORD *)t;
      v39 = t[15];
      v26 = t[11];
      v38 = t[10];
      v40 = t[9];
      v36 = t[8];
      v37 = t[7];
      v32 = t[6];
      v34 = t[5];
      v17 = t[3];
      v18 = t[2];
      v12 = t[1];
      v11 = t[0];
      v57 = t[14];
      v56 = t[13];
      v55 = t[12];
      v41 = t[4];
    }
    else
    {
      v8 = 27 * (t[1] >> 7);
      v9 = 27 * (t[0] >> 7);
      v10 = 27 * (t[2] >> 7);
      v11 = v8 ^ v9 ^ t[1] ^ t[2] ^ t[3] ^ (2 * (t[0] ^ t[1]));
      v12 = v8 ^ v10 ^ t[0] ^ t[2] ^ t[3] ^ (2 * (t[1] ^ t[2]));
      v13 = 27 * (t[3] >> 7);
      v14 = v13 ^ t[0] ^ t[1] ^ t[2] ^ (2 * (t[0] ^ t[3]));
      v15 = v13 ^ t[0] ^ t[1] ^ t[3] ^ (2 * (t[2] ^ t[3]));
      v16 = 27 * (t[5] >> 7);
      v17 = v9 ^ v14;
      v18 = v10 ^ v15;
      v19 = 27 * (t[4] >> 7);
      v58 = t[5] ^ t[6] ^ t[7] ^ v16 ^ v19 ^ (2 * (t[5] ^ t[4]));
      v20 = 27 * (t[6] >> 7);
      v59 = t[6] ^ t[7] ^ v16 ^ v20 ^ t[4] ^ (2 * (t[5] ^ t[6]));
      v21 = 27 * (t[7] >> 7);
      v60 = t[5] ^ t[7] ^ v20 ^ v21 ^ t[4] ^ (2 * (t[6] ^ t[7]));
      v61 = t[5] ^ t[6] ^ v19 ^ v21 ^ t[4] ^ (2 * (t[7] ^ t[4]));
      v22 = 27 * (t[9] >> 7);
      v23 = 27 * (t[8] >> 7);
      v62 = t[9] ^ t[10] ^ t[11] ^ v22 ^ v23 ^ (2 * (t[8] ^ t[9]));
      v24 = 27 * (t[10] >> 7);
      v63 = t[8] ^ t[10] ^ t[11] ^ v22 ^ v24 ^ (2 * (t[9] ^ t[10]));
      v25 = 27 * (t[11] >> 7);
      v64 = t[8] ^ t[9] ^ t[11] ^ v24 ^ v25 ^ (2 * (t[10] ^ t[11]));
      v26 = t[8] ^ t[9] ^ t[10] ^ v23 ^ v25 ^ (2 * (t[8] ^ t[11]));
      v27 = 27 * (t[13] >> 7);
      v28 = 27 * (t[12] >> 7);
      v55 = t[13] ^ t[14] ^ t[15] ^ v27 ^ v28 ^ (2 * (t[12] ^ t[13]));
      v29 = 27 * (t[14] >> 7);
      v56 = t[12] ^ t[14] ^ t[15] ^ v27 ^ v29 ^ (2 * (t[13] ^ t[14]));
      v30 = 27 * (t[15] >> 7);
      v31 = v29 ^ v30 ^ (2 * (t[14] ^ t[15]));
      v32 = v60;
      v33 = v30 ^ (2 * (t[12] ^ t[15]));
      v34 = v59;
      v35 = v28 ^ v33;
      v36 = v62;
      v37 = v61;
      v38 = v64;
      v39 = t[12] ^ t[13] ^ t[14] ^ v35;
      v40 = v63;
      v57 = t[12] ^ t[13] ^ t[15] ^ v31;
      v41 = v58;
    }
    v42 = v4[6] ^ v36;
    v43 = v4[7] ^ v40;
    v44 = *(v4 - 2) ^ v11;
    v45 = *(v4 - 1) ^ v12;
    v46 = *v4 ^ v18;
    v47 = v4[1] ^ v17;
    v48 = v4[3] ^ v34;
    v49 = v4[4] ^ v32;
    v50 = v4[5] ^ v37;
    v51 = v4[8] ^ v38;
    v52 = v4[9] ^ v26;
    v53 = v4[13] ^ v39;
    s[4] = v4[2] ^ v41;
    s[12] = v4[10] ^ v55;
    s[13] = v4[11] ^ v56;
    v54 = v4[12] ^ v57;
    v4 += 16;
    s[8] = v42;
    v3 = v65 + 1;
    s[9] = v43;
    s[0] = v44;
    s[1] = v45;
    s[2] = v46;
    s[3] = v47;
    s[5] = v48;
    s[6] = v49;
    s[7] = v50;
    s[10] = v51;
    s[11] = v52;
    s[14] = v54;
    s[15] = v53;
    v65 = v3;
  }
  while ( v3 <= 10 );
  *(_OWORD *)out = *(_OWORD *)s;
}
