// aes128_encrypt_block = sub_140001A20 (bản strip, IDA không có tên hàm)
__m128i *__fastcall sub_140001A20(const __m128i *a1, const __m128i *a2, __m128i *a3)
{
  __int64 v3; // r9
  __int8 *v4; // rdi
  __int64 v5; // r8
  int v6; // eax
  __int64 v7; // rcx
  char v8; // cl
  char v9; // r10
  char v10; // dl
  __int8 v11; // r15
  __int8 v12; // r12
  char v13; // cl
  char v14; // si
  char v15; // r13
  char v16; // cl
  __int8 v17; // si
  __int8 v18; // r13
  char v19; // r11
  char v20; // dl
  char v21; // cl
  char v22; // cl
  char v23; // r9
  char v24; // dl
  char v25; // cl
  __int8 v26; // bl
  char v27; // cl
  char v28; // r9
  char v29; // dl
  char v30; // cl
  char v31; // al
  __int8 v32; // dl
  char v33; // r14
  __int8 v34; // cl
  char v35; // r14
  __int8 v36; // r9
  __int8 v37; // r8
  __int8 v38; // r11
  __int8 v39; // r14
  __int8 v40; // r10
  __int8 v41; // al
  __int8 v42; // r9
  __int8 v43; // r10
  __int8 v44; // r15
  __int8 v45; // r12
  __int8 v46; // r13
  __int8 v47; // si
  __int8 v48; // cl
  __int8 v49; // dl
  __int8 v50; // r8
  __int8 v51; // r11
  __int8 v52; // bl
  __int8 v53; // r14
  __int8 v54; // al
  _BYTE v56[3]; // [rsp+0h] [rbp-50h]
  __int8 v57; // [rsp+3h] [rbp-4Dh]
  __int8 v58; // [rsp+4h] [rbp-4Ch]
  __int8 v59; // [rsp+5h] [rbp-4Bh]
  __int8 v60; // [rsp+6h] [rbp-4Ah]
  __int8 v61; // [rsp+7h] [rbp-49h]
  __int8 v62; // [rsp+8h] [rbp-48h]
  __int8 v63; // [rsp+9h] [rbp-47h]
  __int64 v64; // [rsp+10h] [rbp-40h]
  __m128i v66; // [rsp+20h] [rbp-30h]
  __m128i v67; // [rsp+38h] [rbp-18h]

  v3 = 1;
  v64 = 1;
  v4 = &a1[1].m128i_i8[2];
  v66 = _mm_xor_si128(_mm_loadu_si128(a1), _mm_loadu_si128(a2));
  do
  {
    v5 = 0;
    v6 = 2;
    do
    {
      v67.m128i_i8[4 * v5] = byte_1400182D0[v66.m128i_u8[4 * (((_BYTE)v6 - 2) & 3)]];
      v67.m128i_i8[4 * v5 + 1] = byte_1400182D0[v66.m128i_u8[4 * (((_BYTE)v6 - 1) & 3) + 1]];
      v7 = 4 * (v6++ & 3u);
      v67.m128i_i8[4 * v5 + 2] = byte_1400182D0[v66.m128i_u8[v7 + 2]];
      v67.m128i_i8[4 * v5++ + 3] = byte_1400182D0[v66.m128i_u8[4 * (v6 & 3) + 3]];
    }
    while ( v5 < 4 );
    if ( v3 >= 10 )
    {
      v66 = v67;
      v39 = v67.m128i_i8[15];
      v26 = v67.m128i_i8[11];
      v38 = v67.m128i_i8[10];
      v40 = v67.m128i_i8[9];
      v36 = v67.m128i_i8[8];
      v37 = v67.m128i_i8[7];
      v32 = v67.m128i_i8[6];
      v34 = v67.m128i_i8[5];
      v17 = v67.m128i_i8[3];
      v18 = v67.m128i_i8[2];
      v12 = v67.m128i_i8[1];
      v11 = v67.m128i_i8[0];
      *(_WORD *)&v56[1] = *(__int16 *)((char *)&v67.m128i_i16[6] + 1);
      v56[0] = v67.m128i_i8[12];
      v41 = v67.m128i_i8[4];
    }
    else
    {
      v8 = 27 * ((unsigned __int8)v67.m128i_i8[1] >> 7);
      v9 = 27 * ((unsigned __int8)v67.m128i_i8[0] >> 7);
      v10 = 27 * ((unsigned __int8)v67.m128i_i8[2] >> 7);
      v11 = v8 ^ v9 ^ v67.m128i_i8[1] ^ v67.m128i_i8[2] ^ v67.m128i_i8[3] ^ (2 * (v67.m128i_i8[0] ^ v67.m128i_i8[1]));
      v12 = v8 ^ v10 ^ v67.m128i_i8[0] ^ v67.m128i_i8[2] ^ v67.m128i_i8[3] ^ (2 * (v67.m128i_i8[1] ^ v67.m128i_i8[2]));
      v13 = 27 * ((unsigned __int8)v67.m128i_i8[3] >> 7);
      v14 = v13 ^ v67.m128i_i8[0] ^ v67.m128i_i8[1] ^ v67.m128i_i8[2] ^ (2 * (v67.m128i_i8[0] ^ v67.m128i_i8[3]));
      v15 = v13 ^ v67.m128i_i8[0] ^ v67.m128i_i8[1] ^ v67.m128i_i8[3] ^ (2 * (v67.m128i_i8[2] ^ v67.m128i_i8[3]));
      v16 = 27 * ((unsigned __int8)v67.m128i_i8[5] >> 7);
      v17 = v9 ^ v14;
      v18 = v10 ^ v15;
      v19 = 27 * ((unsigned __int8)v67.m128i_i8[4] >> 7);
      v57 = v67.m128i_i8[5] ^ v67.m128i_i8[6] ^ v67.m128i_i8[7] ^ v16 ^ v19 ^ (2 * (v67.m128i_i8[5] ^ v67.m128i_i8[4]));
      v20 = 27 * ((unsigned __int8)v67.m128i_i8[6] >> 7);
      v58 = v67.m128i_i8[6] ^ v67.m128i_i8[7] ^ v16 ^ v20 ^ v67.m128i_i8[4] ^ (2 * (v67.m128i_i8[5] ^ v67.m128i_i8[6]));
      v21 = 27 * ((unsigned __int8)v67.m128i_i8[7] >> 7);
      v59 = v67.m128i_i8[5] ^ v67.m128i_i8[7] ^ v20 ^ v21 ^ v67.m128i_i8[4] ^ (2 * (v67.m128i_i8[6] ^ v67.m128i_i8[7]));
      v60 = v67.m128i_i8[5] ^ v67.m128i_i8[6] ^ v19 ^ v21 ^ v67.m128i_i8[4] ^ (2 * (v67.m128i_i8[7] ^ v67.m128i_i8[4]));
      v22 = 27 * ((unsigned __int8)v67.m128i_i8[9] >> 7);
      v23 = 27 * ((unsigned __int8)v67.m128i_i8[8] >> 7);
      v61 = v67.m128i_i8[9]
          ^ v67.m128i_i8[10]
          ^ v67.m128i_i8[11]
          ^ v22
          ^ v23
          ^ (2 * (v67.m128i_i8[8] ^ v67.m128i_i8[9]));
      v24 = 27 * ((unsigned __int8)v67.m128i_i8[10] >> 7);
      v62 = v67.m128i_i8[8]
          ^ v67.m128i_i8[10]
          ^ v67.m128i_i8[11]
          ^ v22
          ^ v24
          ^ (2 * (v67.m128i_i8[9] ^ v67.m128i_i8[10]));
      v25 = 27 * ((unsigned __int8)v67.m128i_i8[11] >> 7);
      v63 = v67.m128i_i8[8]
          ^ v67.m128i_i8[9]
          ^ v67.m128i_i8[11]
          ^ v24
          ^ v25
          ^ (2 * (v67.m128i_i8[10] ^ v67.m128i_i8[11]));
      v26 = v67.m128i_i8[8]
          ^ v67.m128i_i8[9]
          ^ v67.m128i_i8[10]
          ^ v23
          ^ v25
          ^ (2 * (v67.m128i_i8[8] ^ v67.m128i_i8[11]));
      v27 = 27 * ((unsigned __int8)v67.m128i_i8[13] >> 7);
      v28 = 27 * ((unsigned __int8)v67.m128i_i8[12] >> 7);
      v56[0] = v67.m128i_i8[13]
             ^ v67.m128i_i8[14]
             ^ v67.m128i_i8[15]
             ^ v27
             ^ v28
             ^ (2 * (v67.m128i_i8[12] ^ v67.m128i_i8[13]));
      v29 = 27 * ((unsigned __int8)v67.m128i_i8[14] >> 7);
      v56[1] = v67.m128i_i8[12]
             ^ v67.m128i_i8[14]
             ^ v67.m128i_i8[15]
             ^ v27
             ^ v29
             ^ (2 * (v67.m128i_i8[13] ^ v67.m128i_i8[14]));
      v30 = 27 * ((unsigned __int8)v67.m128i_i8[15] >> 7);
      v31 = v29 ^ v30 ^ (2 * (v67.m128i_i8[14] ^ v67.m128i_i8[15]));
      v32 = v59;
      v33 = v30 ^ (2 * (v67.m128i_i8[12] ^ v67.m128i_i8[15]));
      v34 = v58;
      v35 = v28 ^ v33;
      v36 = v61;
      v37 = v60;
      v38 = v63;
      v39 = v67.m128i_i8[12] ^ v67.m128i_i8[13] ^ v67.m128i_i8[14] ^ v35;
      v40 = v62;
      v56[2] = v67.m128i_i8[12] ^ v67.m128i_i8[13] ^ v67.m128i_i8[15] ^ v31;
      v41 = v57;
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
    v66.m128i_i8[4] = v4[2] ^ v41;
    v66.m128i_i16[6] = *((_WORD *)v4 + 5) ^ *(_WORD *)v56;
    v54 = v4[12] ^ v56[2];
    v4 += 16;
    v66.m128i_i8[8] = v42;
    v3 = v64 + 1;
    v66.m128i_i8[9] = v43;
    v66.m128i_i8[0] = v44;
    v66.m128i_i8[1] = v45;
    v66.m128i_i8[2] = v46;
    v66.m128i_i8[3] = v47;
    v66.m128i_i8[5] = v48;
    v66.m128i_i8[6] = v49;
    v66.m128i_i8[7] = v50;
    v66.m128i_i8[10] = v51;
    v66.m128i_i8[11] = v52;
    v66.m128i_i8[14] = v54;
    v66.m128i_i8[15] = v53;
    v64 = v3;
  }
  while ( v3 <= 10 );
  *a3 = v66;
  return a3;
}
