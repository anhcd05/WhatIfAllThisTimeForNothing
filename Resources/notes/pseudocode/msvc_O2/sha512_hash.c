void __fastcall sha512_hash(const unsigned __int8 *msg, size_t n, unsigned __int8 *out)
{
  size_t v3; // rsi
  size_t v6; // r15
  unsigned __int64 v7; // r14
  unsigned __int64 v8; // r12
  unsigned __int64 v9; // r13
  __int64 v10; // r15
  size_t v11; // rax
  __int64 v12; // r9
  unsigned __int8 *v13; // rax
  __int64 i; // r8
  __int64 v15; // rcx
  __int64 v16; // rdx
  unsigned __int64 v17; // rbx
  unsigned __int64 *v18; // r11
  __int64 j; // rdi
  unsigned __int64 v20; // r10
  unsigned __int64 v21; // r9
  unsigned __int64 v22; // r10
  unsigned __int64 v23; // r10
  unsigned __int64 v24; // r9
  unsigned __int64 v25; // r14
  unsigned __int64 v26; // rbx
  unsigned __int64 v27; // r12
  unsigned __int64 v28; // rdi
  unsigned __int64 v29; // r13
  __int64 v30; // r11
  unsigned __int64 v31; // rsi
  unsigned __int64 v32; // r8
  unsigned __int64 v33; // rdx
  unsigned __int64 v34; // rdx
  size_t v35; // [rsp+20h] [rbp-E0h]
  __int64 v36; // [rsp+28h] [rbp-D8h]
  size_t v37; // [rsp+30h] [rbp-D0h]
  unsigned __int64 H[8]; // [rsp+40h] [rbp-C0h]
  unsigned __int64 w[80]; // [rsp+80h] [rbp-80h] BYREF
  unsigned __int8 buf[384]; // [rsp+300h] [rbp+200h] BYREF

  v3 = 8 * n;
  H[3] = 0xA54FF53A5F1D36F1uLL;
  H[4] = 0x510E527FADE682D1LL;
  H[5] = 0x9B05688C2B3E6C1FuLL;
  v6 = ((n + 16) & 0xFFFFFFFFFFFFFF80uLL) + 128;
  v37 = v6;
  H[6] = 0x1F83D9ABFB41BD6BLL;
  v7 = 0x6A09E667F3BCC908LL;
  H[0] = 0x6A09E667F3BCC908LL;
  v8 = 0xBB67AE8584CAA73BuLL;
  H[7] = 0x5BE0CD19137E2179LL;
  v9 = 0x3C6EF372FE94F82BLL;
  H[1] = 0xBB67AE8584CAA73BuLL;
  H[2] = 0x3C6EF372FE94F82BLL;
  memset(a1: buf, Val: 0, Size: sizeof(buf));
  memmove(a1: buf, Src: msg, Size: n);
  buf[n] = 0x80;
  *((_BYTE *)&w[79] + v6 + 7) = v3;
  *((_BYTE *)&w[79] + v6 + 6) = BYTE1(v3);
  *((_BYTE *)&w[79] + v6 + 5) = BYTE2(v3);
  *((_BYTE *)&w[79] + v6 + 4) = BYTE3(v3);
  *((_BYTE *)&w[79] + v6 + 3) = BYTE4(v3);
  *((_BYTE *)&w[79] + v6 + 2) = BYTE5(v3);
  *((_BYTE *)&w[79] + v6 + 1) = BYTE6(v3);
  *((_BYTE *)&w[79] + v6) = HIBYTE(v3);
  v10 = 0;
  v11 = 0;
  v35 = 0;
  if ( v37 != 0 )
  {
    v12 = -641;
    v36 = -641;
    do
    {
      v13 = &buf[v11 + 1];
      for ( i = 16; i != 0; --i )
      {
        v15 = *v13;
        v16 = *(v13 - 1);
        v13 += 8;
        *(_QWORD *)&v13[v12 - 8] = *(v13 - 2)
                                 | ((*(v13 - 3)
                                   | ((*(v13 - 4)
                                     | ((*(v13 - 5)
                                       | ((*(v13 - 6) | ((*(v13 - 7) | ((v15 | (v16 << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
      }
      v17 = w[14];
      v18 = &w[14];
      for ( j = 16; j != 0; --j )
      {
        v20 = *(v18 - 13);
        v18 += 4;
        v21 = *(v18 - 9)
            + *(v18 - 18)
            + ((v20 >> 7) ^ __ROR8__(v20, 1) ^ __ROR8__(v20, 8))
            + ((v17 >> 6) ^ __ROL8__(v17, 3) ^ __ROR8__(v17, 19));
        *(v18 - 2) = v21;
        v22 = *(v18 - 8)
            + ((*(v18 - 16) >> 7) ^ __ROR8__(*(v18 - 16), 1) ^ __ROR8__(*(v18 - 16), 8))
            + ((*(v18 - 3) >> 6) ^ __ROL8__(*(v18 - 3), 3) ^ __ROR8__(*(v18 - 3), 19))
            + v20;
        *(v18 - 1) = v22;
        v17 = *(v18 - 16)
            + *(v18 - 7)
            + ((*(v18 - 15) >> 7) ^ __ROR8__(*(v18 - 15), 1) ^ __ROR8__(*(v18 - 15), 8))
            + ((v21 >> 6) ^ __ROL8__(v21, 3) ^ __ROR8__(v21, 19));
        *v18 = v17;
        v18[1] = *(v18 - 15)
               + *(v18 - 6)
               + ((*(v18 - 14) >> 7) ^ __ROR8__(*(v18 - 14), 1) ^ __ROR8__(*(v18 - 14), 8))
               + ((v22 >> 6) ^ __ROL8__(v22, 3) ^ __ROR8__(v22, 19));
      }
      v23 = H[4];
      v24 = v7;
      v25 = H[6];
      v26 = v8;
      v27 = H[3];
      v28 = v9;
      v29 = H[7];
      v30 = 0;
      v31 = H[5];
      do
      {
        v32 = v29
            + w[v30]
            + SHA512_K[v30]
            + (v23 & v31 ^ v25 & ~v23)
            + (__ROR8__(v23, 14) ^ __ROR8__(v23, 18) ^ __ROL8__(v23, 23));
        v29 = v25;
        v33 = (v24 & v26 ^ v28 & (v24 ^ v26)) + (__ROL8__(v24, 25) ^ __ROR8__(v24, 28) ^ __ROL8__(v24, 30));
        v25 = v31;
        v31 = v23;
        ++v30;
        v23 = v32 + v27;
        v27 = v28;
        v28 = v26;
        v26 = v24;
        v24 = v33 + v32;
      }
      while ( v30 < 80 );
      H[0] += v24;
      v10 = 0;
      v12 = v36 - 128;
      H[1] += v26;
      v11 = v35 + 128;
      H[2] += v28;
      H[3] += v27;
      H[6] += v25;
      H[7] += v29;
      H[4] += v23;
      H[5] += v31;
      v7 = H[0];
      v8 = H[1];
      v9 = H[2];
      v35 = v11;
      v36 -= 128;
    }
    while ( v11 < v37 );
  }
  do
  {
    v34 = H[(unsigned __int64)v10 / 8];
    out[v10 + 7] = v34;
    out[v10] = HIBYTE(v34);
    out[v10 + 1] = BYTE6(v34);
    out[v10 + 2] = BYTE5(v34);
    out[v10 + 3] = BYTE4(v34);
    out[v10 + 4] = BYTE3(v34);
    out[v10 + 5] = BYTE2(v34);
    out[v10 + 6] = BYTE1(v34);
    v10 += 8;
  }
  while ( v10 < 64 );
}
