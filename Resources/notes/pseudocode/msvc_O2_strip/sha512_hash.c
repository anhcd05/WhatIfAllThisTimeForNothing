// sha512_hash = sub_1400056C0 (bản strip, IDA không có tên hàm)
unsigned __int64 __fastcall sub_1400056C0(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rsi
  unsigned __int64 v6; // r15
  __int64 v7; // r14
  unsigned __int64 v8; // r12
  __int64 v9; // r13
  __int64 v10; // r15
  unsigned __int64 v11; // rax
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
  __int64 v23; // r10
  __int64 v24; // r9
  __int64 v25; // r14
  unsigned __int64 v26; // rbx
  unsigned __int64 v27; // r12
  __int64 v28; // rdi
  __int64 v29; // r13
  __int64 v30; // r11
  unsigned __int64 v31; // rsi
  unsigned __int64 v32; // r8
  unsigned __int64 v33; // rdx
  unsigned __int64 v34; // rdx
  unsigned __int64 result; // rax
  unsigned __int64 v36; // [rsp+20h] [rbp-E0h]
  __int64 v37; // [rsp+28h] [rbp-D8h]
  unsigned __int64 v38; // [rsp+30h] [rbp-D0h]
  __int64 v40; // [rsp+40h] [rbp-C0h]
  unsigned __int64 v41; // [rsp+48h] [rbp-B8h]
  __int64 v42; // [rsp+50h] [rbp-B0h]
  unsigned __int64 v43; // [rsp+58h] [rbp-A8h]
  __int64 v44; // [rsp+60h] [rbp-A0h]
  unsigned __int64 v45; // [rsp+68h] [rbp-98h]
  __int64 v46; // [rsp+70h] [rbp-90h]
  __int64 v47; // [rsp+78h] [rbp-88h]
  _QWORD v48[14]; // [rsp+80h] [rbp-80h]
  _QWORD v49[66]; // [rsp+F0h] [rbp-10h] BYREF
  _BYTE v50[384]; // [rsp+300h] [rbp+200h] BYREF

  v3 = 8 * a2;
  v43 = 0xA54FF53A5F1D36F1uLL;
  v44 = 0x510E527FADE682D1LL;
  v45 = 0x9B05688C2B3E6C1FuLL;
  v6 = ((a2 + 16) & 0xFFFFFFFFFFFFFF80uLL) + 128;
  v38 = v6;
  v46 = 0x1F83D9ABFB41BD6BLL;
  v7 = 0x6A09E667F3BCC908LL;
  v40 = 0x6A09E667F3BCC908LL;
  v8 = 0xBB67AE8584CAA73BuLL;
  v47 = 0x5BE0CD19137E2179LL;
  v9 = 0x3C6EF372FE94F82BLL;
  v41 = 0xBB67AE8584CAA73BuLL;
  v42 = 0x3C6EF372FE94F82BLL;
  sub_140007EA0(a1: v50, a2: 0, a3: 384);
  sub_140007A40(a1: v50, a2: a1, a3: a2);
  v50[a2] = 0x80;
  *((_BYTE *)&v49[65] + v6 + 7) = v3;
  *((_BYTE *)&v49[65] + v6 + 6) = BYTE1(v3);
  *((_BYTE *)&v49[65] + v6 + 5) = BYTE2(v3);
  *((_BYTE *)&v49[65] + v6 + 4) = BYTE3(v3);
  *((_BYTE *)&v49[65] + v6 + 3) = BYTE4(v3);
  *((_BYTE *)&v49[65] + v6 + 2) = BYTE5(v3);
  *((_BYTE *)&v49[65] + v6 + 1) = BYTE6(v3);
  *((_BYTE *)&v49[65] + v6) = HIBYTE(v3);
  v10 = 0;
  v11 = 0;
  v36 = 0;
  if ( v38 != 0 )
  {
    v12 = -641;
    v37 = -641;
    do
    {
      v13 = &v50[v11 + 1];
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
      v17 = v49[0];
      v18 = v49;
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
      v23 = v44;
      v24 = v7;
      v25 = v46;
      v26 = v8;
      v27 = v43;
      v28 = v9;
      v29 = v47;
      v30 = 0;
      v31 = v45;
      do
      {
        v32 = v29
            + v48[v30]
            + *(_QWORD *)((char *)&unk_140018AF0 + v30 * 8)
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
      v40 += v24;
      v10 = 0;
      v12 = v37 - 128;
      v41 += v26;
      v11 = v36 + 128;
      v42 += v28;
      v43 += v27;
      v46 += v25;
      v47 += v29;
      v44 += v23;
      v45 += v31;
      v7 = v40;
      v8 = v41;
      v9 = v42;
      v36 = v11;
      v37 -= 128;
    }
    while ( v11 < v38 );
  }
  do
  {
    v34 = *(__int64 *)((char *)&v40 + v10);
    *(_BYTE *)(a3 + v10 + 7) = v34;
    *(_BYTE *)(v10 + a3) = HIBYTE(v34);
    *(_BYTE *)(a3 + v10 + 1) = BYTE6(v34);
    *(_BYTE *)(a3 + v10 + 2) = BYTE5(v34);
    *(_BYTE *)(a3 + v10 + 3) = BYTE4(v34);
    *(_BYTE *)(a3 + v10 + 4) = BYTE3(v34);
    *(_BYTE *)(a3 + v10 + 5) = BYTE2(v34);
    result = v34 >> 8;
    *(_BYTE *)(a3 + v10 + 6) = BYTE1(v34);
    v10 += 8;
  }
  while ( v10 < 64 );
  return result;
}
