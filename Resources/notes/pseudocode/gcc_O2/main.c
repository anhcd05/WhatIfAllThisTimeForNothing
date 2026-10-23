int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rbp
  size_t v4; // rax
  char *v5; // rdi
  const char *v6; // rsi
  __int64 v7; // rbx
  __int64 v8; // rcx
  __int64 v9; // rax
  int v10; // eax
  char *v11; // rdi
  char *v12; // rsi
  __int64 v13; // rcx
  __int64 v14; // rax
  char *v15; // rdi
  char *v16; // rsi
  __int64 v17; // rcx
  __int64 v18; // rax
  char *v19; // rdi
  char *v20; // rsi
  __int64 v21; // rcx
  __int64 v22; // rax
  char *v23; // rdi
  char *v24; // rsi
  __int64 v25; // rcx
  __int64 v26; // rax
  char *v27; // rdi
  char *v28; // rsi
  __int64 v29; // rcx
  __int64 v30; // rax
  char *v31; // rdi
  char *v32; // rsi
  __int64 v33; // rcx
  __int64 v34; // rax
  char *v35; // rdi
  char *v36; // rsi
  __int64 v37; // rcx
  __int64 v38; // rax
  char *v39; // rdi
  char *v40; // rsi
  __int64 v41; // rcx
  __int64 v42; // rax
  unsigned int v43; // eax
  __int64 v44; // rdi
  __int64 v45; // rsi
  int v46; // eax
  int v47; // edx
  char *v48; // rdi
  char *v49; // rsi
  __int64 v50; // rcx
  __int64 v51; // rax
  char *v52; // rdi
  char *v53; // rsi
  __int64 v54; // rcx
  __int64 v55; // rax
  char *v56; // rdi
  char *v57; // rsi
  __int64 v58; // rcx
  __int64 v59; // rax
  size_t v60; // r12
  char *v61; // rsi
  _BYTE *v62; // rdi
  __int64 v63; // rcx
  __int64 v64; // rax
  __int64 v65; // rax
  __int64 v66; // rcx
  _DWORD *v67; // rdi
  _DWORD *v68; // rsi
  size_t i; // r14
  __int64 v70; // rcx
  __int64 v71; // rax
  _DWORD *v72; // rdi
  _DWORD *v73; // rsi
  void *v74; // rax
  int v75; // eax
  __int64 v76; // rcx
  __int64 v77; // rax
  _DWORD *v78; // rdi
  _DWORD *v79; // rsi
  size_t j; // r11
  __int64 v81; // r11
  __int64 v82; // rcx
  __int64 v83; // rax
  _DWORD *v84; // rdi
  _DWORD *v85; // rsi
  size_t k; // r11
  __int64 v87; // r11
  int v88; // eax
  __int64 v89; // rcx
  __int64 v90; // rdx
  __int32 *v91; // rdi
  __int32 *v92; // rsi
  int v93; // eax
  char *v94; // rsi
  size_t v95; // r12
  _BYTE *v96; // rdi
  __int64 v97; // rcx
  __int64 v98; // rax
  __int64 v99; // rcx
  __int64 v100; // rax
  _DWORD *v101; // rdi
  _DWORD *v102; // rsi
  __int64 v103; // rax
  __int64 v104; // rax
  int v105; // eax
  char *v106; // rdi
  char *v107; // rsi
  __int64 v108; // rcx
  __int64 v109; // rax
  char *v110; // rdi
  char *v111; // rsi
  __int64 v112; // rcx
  __int64 v113; // rax
  int v114; // eax
  int v115; // eax
  int v116; // eax
  int v117; // eax
  int v118; // eax
  void *v120; // [rsp+8h] [rbp-B90h]
  __int64 v121; // [rsp+18h] [rbp-B80h]
  __int64 v122; // [rsp+18h] [rbp-B80h]
  __int64 v123; // [rsp+28h] [rbp-B70h] BYREF
  __int64 v124; // [rsp+30h] [rbp-B68h] BYREF
  __int64 v125; // [rsp+38h] [rbp-B60h] BYREF
  __int64 v126; // [rsp+40h] [rbp-B58h] BYREF
  __int64 v127; // [rsp+48h] [rbp-B50h] BYREF
  __int64 v128; // [rsp+50h] [rbp-B48h] BYREF
  int v129; // [rsp+58h] [rbp-B40h]
  char src[256]; // [rsp+60h] [rbp-B38h] BYREF
  __m128i v131[16]; // [rsp+160h] [rbp-A38h] BYREF
  char v132[320]; // [rsp+260h] [rbp-938h] BYREF
  _BYTE v133[320]; // [rsp+3A0h] [rbp-7F8h] BYREF
  _BYTE v134[320]; // [rsp+4E0h] [rbp-6B8h] BYREF
  _BYTE s1[320]; // [rsp+620h] [rbp-578h] BYREF
  char v136[1080]; // [rsp+760h] [rbp-438h] BYREF

  v3 = "Hello, CyberSeaGame!";
  if ( argc > 1 )
    v3 = argv[1];
  v4 = strlen(s: v3);
  v5 = src;
  v6 = v3;
  v7 = v4;
  if ( v4 > 0xC8 )
    v7 = 200;
  if ( (unsigned int)v7 >= 8 )
  {
    v8 = (unsigned int)v7 >> 3;
    qmemcpy(src, v3, 8 * v8);
    v6 = &v3[8 * v8];
    v5 = &src[8 * v8];
  }
  v9 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v5 = *(_DWORD *)v6;
    v9 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v5[v9] = *(_WORD *)&v6[v9];
    v9 += 2;
  }
  if ( (v7 & 1) != 0 )
    v5[v9] = v6[v9];
  printf(format: "input: %.*s\n", v7, v3);
  b64_encode(a1: (__int64)src, a2: v7, a3: v136);
  printf(format: "base64: %s\n", v136);
  v10 = b64_decode(a1: v136, a2: (__int64)v132);
  printf(format: "base64_dec: %.*s\n", v10, v132);
  b32_encode(a1: (unsigned __int8 *)src, a2: v7, a3: v136);
  printf(format: "base32: %s\n", v136);
  b58_encode(a1: (__int64)src, a2: v7, a3: v136);
  printf(format: "base58: %s\n", v136);
  a85_encode(a1: (__int64)src, a2: v7, a3: v136);
  printf(format: "ascii85: %s\n", v136);
  hex_encode(a1: (__int64)src, a2: v7, a3: (__int64)v136);
  printf(format: "hex: %s\n", v136);
  v11 = v132;
  v12 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v13 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v13);
    v12 = &src[8 * v13];
    v11 = &v132[8 * v13];
  }
  v14 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v11 = *(_DWORD *)v12;
    v14 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v11[v14] = *(_WORD *)&v12[v14];
    v14 += 2;
  }
  if ( (v7 & 1) != 0 )
    v11[v14] = v12[v14];
  rot13(a1: v132, a2: v7);
  ph(a1: "rot13", a2: v132, a3: v7);
  v15 = v132;
  v16 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v17 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v17);
    v16 = &src[8 * v17];
    v15 = &v132[8 * v17];
  }
  v18 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v15 = *(_DWORD *)v16;
    v18 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v15[v18] = *(_WORD *)&v16[v18];
    v18 += 2;
  }
  if ( (v7 & 1) != 0 )
    v15[v18] = v16[v18];
  xor_single(a1: v132, a2: v7, a3: 90);
  ph(a1: "xor_single_5a", a2: v132, a3: v7);
  v19 = v132;
  v20 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v21 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v21);
    v20 = &src[8 * v21];
    v19 = &v132[8 * v21];
  }
  v22 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v19 = *(_DWORD *)v20;
    v22 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v19[v22] = *(_WORD *)&v20[v22];
    v22 += 2;
  }
  if ( (v7 & 1) != 0 )
    v19[v22] = v20[v22];
  xor_repeat(a1: v132, a2: v7, a3: "KEY", a4: 3);
  ph(a1: "xor_repeat_KEY", a2: v132, a3: v7);
  v23 = v132;
  v24 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v25 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v25);
    v24 = &src[8 * v25];
    v23 = &v132[8 * v25];
  }
  v26 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v23 = *(_DWORD *)v24;
    v26 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v23[v26] = *(_WORD *)&v24[v26];
    v26 += 2;
  }
  if ( (v7 & 1) != 0 )
    v23[v26] = v24[v26];
  op_add(a1: v132, a2: v7, a3: 7);
  ph(a1: "add_7", a2: v132, a3: v7);
  v27 = v132;
  v28 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v29 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v29);
    v28 = &src[8 * v29];
    v27 = &v132[8 * v29];
  }
  v30 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v27 = *(_DWORD *)v28;
    v30 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v27[v30] = *(_WORD *)&v28[v30];
    v30 += 2;
  }
  if ( (v7 & 1) != 0 )
    v27[v30] = v28[v30];
  op_sub(a1: v132, a2: v7, a3: 7);
  ph(a1: "sub_7", a2: v132, a3: v7);
  v31 = v132;
  v32 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v33 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v33);
    v32 = &src[8 * v33];
    v31 = &v132[8 * v33];
  }
  v34 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v31 = *(_DWORD *)v32;
    v34 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v31[v34] = *(_WORD *)&v32[v34];
    v34 += 2;
  }
  if ( (v7 & 1) != 0 )
    v31[v34] = v32[v34];
  op_not(a1: v132, a2: v7);
  ph(a1: "not", a2: v132, a3: v7);
  v35 = v132;
  v36 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v37 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v37);
    v36 = &src[8 * v37];
    v35 = &v132[8 * v37];
  }
  v38 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v35 = *(_DWORD *)v36;
    v38 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v35[v38] = *(_WORD *)&v36[v38];
    v38 += 2;
  }
  if ( (v7 & 1) != 0 )
    v35[v38] = v36[v38];
  op_rol8(a1: v132, a2: v7, a3: 3);
  ph(a1: "rol8_3", a2: v132, a3: v7);
  v39 = v132;
  v40 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v41 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v41);
    v40 = &src[8 * v41];
    v39 = &v132[8 * v41];
  }
  v42 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v39 = *(_DWORD *)v40;
    v42 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v39[v42] = *(_WORD *)&v40[v42];
    v42 += 2;
  }
  if ( (v7 & 1) != 0 )
    v39[v42] = v40[v42];
  op_ror8(a1: v132, a2: v7, a3: 3);
  ph(a1: "ror8_3", a2: v132, a3: v7);
  v43 = op_ror32(a1: 305419896, a2: 8);
  v46 = op_rol32(a1: v44, a2: v45, a3: v43);
  printf(format: "rol32: %08x ror32: %08x\n", v46, v47);
  v48 = v132;
  v49 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v50 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v50);
    v49 = &src[8 * v50];
    v48 = &v132[8 * v50];
  }
  v51 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v48 = *(_DWORD *)v49;
    v51 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v48[v51] = *(_WORD *)&v49[v51];
    v51 += 2;
  }
  if ( (v7 & 1) != 0 )
    v48[v51] = v49[v51];
  op_reverse(a1: v132, a2: v7);
  ph(a1: "reverse", a2: v132, a3: v7);
  v52 = v132;
  v53 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v54 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v54);
    v53 = &src[8 * v54];
    v52 = &v132[8 * v54];
  }
  v55 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v52 = *(_DWORD *)v53;
    v55 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v52[v55] = *(_WORD *)&v53[v55];
    v55 += 2;
  }
  if ( (v7 & 1) != 0 )
    v52[v55] = v53[v55];
  mix_chain(a1: v132, a2: v7);
  ph(a1: "mix_chain", a2: v132, a3: v7);
  v56 = v132;
  v57 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v58 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v58);
    v57 = &src[8 * v58];
    v56 = &v132[8 * v58];
  }
  v59 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v56 = *(_DWORD *)v57;
    v59 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v56[v59] = *(_WORD *)&v57[v59];
    v59 += 2;
  }
  if ( (v7 & 1) != 0 )
    v56[v59] = v57[v59];
  rc4_crypt(a1: "CyberSea", a2: 8, a3: v132, a4: v7);
  ph(a1: "rc4_CyberSea", a2: v132, a3: v7);
  v60 = (v7 + 7) & 0xFFFFFFFFFFFFFFF8LL;
  if ( v60 == 0 )
    v60 = 8;
  memset(v133, 0, sizeof(v133));
  v61 = src;
  v62 = v133;
  if ( (unsigned int)v7 >= 8 )
  {
    v63 = (unsigned int)v7 >> 3;
    qmemcpy(v133, src, 8 * v63);
    v61 = &src[8 * v63];
    v62 = &v133[8 * v63];
  }
  v64 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v62 = *(_DWORD *)v61;
    v64 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v62[v64] = *(_WORD *)&v61[v64];
    v64 += 2;
  }
  if ( (v7 & 1) != 0 )
    v62[v64] = v61[v64];
  v65 = 0;
  v66 = (unsigned int)v60 >> 3;
  qmemcpy(v134, v133, 8 * v66);
  v68 = &v133[8 * v66];
  v67 = &v134[8 * v66];
  if ( (v60 & 4) != 0 )
  {
    *v67 = *v68;
    v65 = 4;
  }
  if ( (v60 & 2) != 0 )
  {
    *(_WORD *)((char *)v67 + v65) = *(_WORD *)((char *)v68 + v65);
    v65 += 2;
  }
  if ( (v60 & 1) != 0 )
    *((_BYTE *)v67 + v65) = *((_BYTE *)v68 + v65);
  for ( i = 0; i < v60; i += 8LL )
  {
    v124 = *(_QWORD *)&v134[i];
    tea_encrypt(a1: &v124, a2: &tk_0);
    *(_QWORD *)&v134[i] = v124;
  }
  ph(a1: "tea_ecb", a2: v134, a3: v60);
  v70 = (unsigned int)v60 >> 3;
  v71 = 0;
  qmemcpy(s1, v134, 8 * v70);
  v73 = &v134[8 * v70];
  v72 = &s1[8 * v70];
  if ( (v60 & 4) != 0 )
  {
    *v72 = *v73;
    v71 = 4;
  }
  if ( (v60 & 2) != 0 )
  {
    *(_WORD *)((char *)v72 + v71) = *(_WORD *)((char *)v73 + v71);
    v71 += 2;
  }
  if ( (v60 & 1) != 0 )
    *((_BYTE *)v72 + v71) = *((_BYTE *)v73 + v71);
  v74 = nullptr;
  do
  {
    v120 = v74;
    v125 = *(_QWORD *)&s1[(_QWORD)v74];
    tea_decrypt(a1: &v125, a2: &tk_0);
    *(_QWORD *)&s1[(_QWORD)v120] = v125;
    v74 = (char *)v120 + 8;
  }
  while ( (unsigned __int64)v120 + 8 < v60 );
  v75 = memcmp(s1, s2: v133, n: v60);
  printf(format: "tea_dec_ok: %d\n", v75 == 0);
  v76 = (unsigned int)v60 >> 3;
  v77 = 0;
  qmemcpy(v134, v133, 8 * v76);
  v79 = &v133[8 * v76];
  v78 = &v134[8 * v76];
  if ( (v60 & 4) != 0 )
  {
    *v78 = *v79;
    v77 = 4;
  }
  if ( (v60 & 2) != 0 )
  {
    *(_WORD *)((char *)v78 + v77) = *(_WORD *)((char *)v79 + v77);
    v77 += 2;
  }
  if ( (v60 & 1) != 0 )
    *((_BYTE *)v78 + v77) = *((_BYTE *)v79 + v77);
  for ( j = 0; j < v60; j = v81 + 8 )
  {
    v126 = *(_QWORD *)&v134[j];
    xtea_encrypt(a1: &v126, a2: &tk_0);
    *(_QWORD *)&v134[v81] = v126;
  }
  ph(a1: "xtea_ecb", a2: v134, a3: v60);
  v82 = (unsigned int)v60 >> 3;
  v83 = 0;
  qmemcpy(s1, v134, 8 * v82);
  v85 = &v134[8 * v82];
  v84 = &s1[8 * v82];
  if ( (v60 & 4) != 0 )
  {
    *v84 = *v85;
    v83 = 4;
  }
  if ( (v60 & 2) != 0 )
  {
    *(_WORD *)((char *)v84 + v83) = *(_WORD *)((char *)v85 + v83);
    v83 += 2;
  }
  if ( (v60 & 1) != 0 )
    *((_BYTE *)v84 + v83) = *((_BYTE *)v85 + v83);
  for ( k = 0; k < v60; k = v87 + 8 )
  {
    v127 = *(_QWORD *)&s1[k];
    xtea_decrypt(a1: &v127, a2: &tk_0);
    *(_QWORD *)&s1[v87] = v127;
  }
  v88 = memcmp(s1, s2: v133, n: v60);
  printf(format: "xtea_dec_ok: %d\n", v88 == 0);
  v89 = (unsigned int)v60 >> 3;
  v90 = 0;
  qmemcpy(v131, v133, 8 * v89);
  v92 = (__int32 *)&v133[8 * v89];
  v91 = &v131[0].m128i_i32[2 * v89];
  if ( (v60 & 4) != 0 )
  {
    *v91 = *v92;
    v90 = 4;
  }
  if ( (v60 & 2) != 0 )
  {
    *(_WORD *)((char *)v91 + v90) = *(_WORD *)((char *)v92 + v90);
    v90 += 2;
  }
  if ( (v60 & 1) != 0 )
    *((_BYTE *)v91 + v90) = *((_BYTE *)v92 + v90);
  xxtea_encrypt(a1: v131, a2: (unsigned int)(v60 >> 2), a3: &tk_0);
  ph(a1: "xxtea", a2: v131, a3: v60);
  xxtea_decrypt(a1: v131, a2: (unsigned int)(v60 >> 2), a3: &tk_0);
  v93 = memcmp(s1: v131, s2: v133, n: v60);
  printf(format: "xxtea_dec_ok: %d\n", v93 == 0);
  aes128_key_expand(a1: (const __m128i *)"0123456789abcdef", a2: v131);
  v94 = src;
  v95 = (v7 + 15) & 0xFFFFFFFFFFFFFFF0LL;
  if ( v95 == 0 )
    v95 = 16;
  memset(v133, 0, sizeof(v133));
  v96 = v133;
  if ( (unsigned int)v7 >= 8 )
  {
    v97 = (unsigned int)v7 >> 3;
    qmemcpy(v133, src, 8 * v97);
    v94 = &src[8 * v97];
    v96 = &v133[8 * v97];
  }
  v98 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v96 = *(_DWORD *)v94;
    v98 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v96[v98] = *(_WORD *)&v94[v98];
    v98 += 2;
  }
  if ( (v7 & 1) != 0 )
    v96[v98] = v94[v98];
  v99 = (unsigned int)v95 >> 3;
  v100 = 0;
  qmemcpy(v134, v133, 8 * v99);
  v102 = &v133[8 * v99];
  v101 = &v134[8 * v99];
  if ( (v95 & 4) != 0 )
  {
    *v101 = *v102;
    v100 = 4;
  }
  if ( (v95 & 2) != 0 )
  {
    *(_WORD *)((char *)v101 + v100) = *(_WORD *)((char *)v102 + v100);
    v100 += 2;
  }
  if ( (v95 & 1) != 0 )
    *((_BYTE *)v101 + v100) = *((_BYTE *)v102 + v100);
  v103 = 0;
  do
  {
    v121 = v103;
    aes128_encrypt_block(a1: v131, a2: (const __m128i *)&v133[v103], a3: (__m128i *)&v134[v103]);
    v103 = v121 + 16;
  }
  while ( v121 + 16 < v95 );
  ph(a1: "aes128_ecb", a2: v134, a3: v95);
  v104 = 0;
  do
  {
    v122 = v104;
    aes128_decrypt_block(a1: v131, a2: (const __m128i *)&v134[v104], a3: (__m128i *)&s1[v104]);
    v104 = v122 + 16;
  }
  while ( v122 + 16 < v95 );
  v105 = memcmp(s1, s2: v133, n: v95);
  printf(format: "aes_dec_ok: %d\n", v105 == 0);
  v129 = 185207048;
  v106 = v132;
  v107 = src;
  v131[0] = _mm_load_si128((const __m128i *)&xmmword_6F40);
  v128 = 0x706050403020100LL;
  v123 = 0x706050403020100LL;
  v131[1] = _mm_load_si128((const __m128i *)&xmmword_6F50);
  if ( (unsigned int)v7 >= 8 )
  {
    v108 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v108);
    v107 = &src[8 * v108];
    v106 = &v132[8 * v108];
  }
  v109 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v106 = *(_DWORD *)v107;
    v109 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v106[v109] = *(_WORD *)&v107[v109];
    v109 += 2;
  }
  if ( (v7 & 1) != 0 )
    v106[v109] = v107[v109];
  chacha20_xor(a1: v131, a2: (int *)&v128, a3: (__int64)v132, a4: v7);
  ph(a1: "chacha20", a2: v132, a3: v7);
  v110 = v132;
  v111 = src;
  if ( (unsigned int)v7 >= 8 )
  {
    v112 = (unsigned int)v7 >> 3;
    qmemcpy(v132, src, 8 * v112);
    v111 = &src[8 * v112];
    v110 = &v132[8 * v112];
  }
  v113 = 0;
  if ( (v7 & 4) != 0 )
  {
    *(_DWORD *)v110 = *(_DWORD *)v111;
    v113 = 4;
  }
  if ( (v7 & 2) != 0 )
  {
    *(_WORD *)&v110[v113] = *(_WORD *)&v111[v113];
    v113 += 2;
  }
  if ( (v7 & 1) != 0 )
    v110[v113] = v111[v113];
  salsa20_xor(a1: v131, a2: &v123, a3: v132, a4: v7);
  ph(a1: "salsa20", a2: v132, a3: v7);
  md5_hash(src, n: v7);
  ph(a1: "md5", a2: v131, a3: 16);
  sha1_hash(src, n: v7);
  ph(a1: "sha1", a2: v131, a3: 20);
  sha256_hash(src, n: v7);
  ph(a1: "sha256", a2: v131, a3: 32);
  sha512_hash(src, n: v7);
  ph(a1: "sha512", a2: v131, a3: 64);
  v114 = crc32_table(a1: src, a2: v7);
  printf(format: "crc32_table: %08x\n", v114);
  v115 = crc32_bitwise(a1: (unsigned __int8 *)src, a2: v7);
  printf(format: "crc32_bitwise: %08x\n", v115);
  v116 = adler32_hash(a1: (unsigned __int8 *)src, a2: v7);
  printf(format: "adler32: %08x\n", v116);
  v117 = fnv1a_hash(a1: (unsigned __int8 *)src, a2: v7);
  printf(format: "fnv1a: %08x\n", v117);
  v118 = djb2_hash(a1: (unsigned __int8 *)src, a2: v7);
  printf(format: "djb2: %08x\n", v118);
  return 0;
}
