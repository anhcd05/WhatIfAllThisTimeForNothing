// a85_encode = sub_140001010 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140001010(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rdi
  unsigned __int64 v6; // rsi
  unsigned __int8 *v7; // rbx
  __int64 v8; // r14
  unsigned int v9; // ecx
  __int64 v10; // rax
  unsigned int v11; // r10d
  unsigned __int64 v12; // rbp
  unsigned int v13; // r9d
  unsigned int v14; // r8d
  unsigned int v15; // r9d
  __int64 result; // rax
  int v17; // [rsp+20h] [rbp-48h] BYREF
  char v18; // [rsp+24h] [rbp-44h]

  v3 = 0;
  v6 = 0;
  if ( a2 >= 4 )
  {
    v7 = (unsigned __int8 *)(a1 + 1);
    v8 = 3 - a1;
    do
    {
      v9 = v7[2] | ((v7[1] | ((*v7 | (*(v7 - 1) << 8)) << 8)) << 8);
      if ( v9 != 0 )
      {
        v11 = v9 / 0x55 / 0x55;
        HIBYTE(v17) = v9 / 0x55 % 0x55 + 33;
        BYTE2(v17) = v11 % 0x55 + 33;
        BYTE1(v17) = v11 / 0x55 % 0x55 + 33;
        LOBYTE(v17) = v11 / 0x55 / 0x55 % 0x55 + 33;
        *(_DWORD *)(a3 + v3) = v17;
        v10 = 5;
        *(_BYTE *)(a3 + v3 + 4) = v9 % 0x55 + 33;
      }
      else
      {
        *(_BYTE *)(a3 + v3) = 122;
        v10 = 1;
      }
      v7 += 4;
      v3 += v10;
      v6 += 4LL;
    }
    while ( (unsigned __int64)&v7[v8] <= a2 );
  }
  if ( v6 >= a2 )
  {
    *(_BYTE *)(a3 + v3) = 0;
    return v3;
  }
  else
  {
    v12 = a2 - v6;
    v17 = 0;
    sub_140007A40(a1: &v17, a2: a1 + v6, a3: a2 - v6);
    v13 = HIBYTE(v17) | ((BYTE2(v17) | ((BYTE1(v17) | ((unsigned __int8)v17 << 8)) << 8)) << 8);
    v14 = v13 / 0x55;
    v18 = v13 % 0x55 + 33;
    v15 = v13 / 0x55 / 0x55;
    HIBYTE(v17) = v14 - 85 * v15 + 33;
    BYTE2(v17) = v15 % 0x55 + 33;
    BYTE1(v17) = v15 / 0x55 % 0x55 + 33;
    LOBYTE(v17) = v15 / 0x55 / 0x55 % 0x55 + 33;
    sub_140007A40(a1: a3 + v3, a2: &v17, a3: v12 + 1);
    result = v3 + v12 + 1;
    *(_BYTE *)(a3 + result) = 0;
  }
  return result;
}
