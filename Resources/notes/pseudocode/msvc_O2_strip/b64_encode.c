// b64_encode = sub_1400022C0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400022C0(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // r10
  __int64 result; // rax
  unsigned __int8 *v7; // r11
  __int64 v8; // rbx
  __int64 v9; // rcx
  __int64 v10; // rdx
  unsigned __int64 v11; // rdx
  __int64 v12; // r9
  __int64 v13; // rdx
  unsigned __int64 v14; // rdx

  v3 = 0;
  result = 0;
  if ( a2 > 2 )
  {
    v7 = (unsigned __int8 *)(a1 + 1);
    v8 = 1 - a1;
    do
    {
      v9 = *v7;
      v3 += 3;
      v10 = *(v7 - 1);
      v7 += 3;
      v11 = *(v7 - 2) | ((v9 | (v10 << 8)) << 8);
      *(_BYTE *)(result + a3) = aAbcdefghijklmn_1[v11 >> 18];
      *(_BYTE *)(result + a3 + 1) = aAbcdefghijklmn_1[(v11 >> 12) & 0x3F];
      *(_BYTE *)(result + a3 + 2) = aAbcdefghijklmn_1[(v11 >> 6) & 0x3F];
      *(_BYTE *)(result + a3 + 3) = aAbcdefghijklmn_1[v11 & 0x3F];
      result += 4;
    }
    while ( (unsigned __int64)&v7[v8] < a2 );
  }
  v12 = a2 - v3;
  if ( v12 == 1 )
  {
    v13 = (16 * *(unsigned __int8 *)(v3 + a1)) & 0x3F;
    *(_BYTE *)(result + a3) = aAbcdefghijklmn_1[(unsigned __int64)*(unsigned __int8 *)(v3 + a1) << 16 >> 18];
    *(_BYTE *)(result + a3 + 1) = aAbcdefghijklmn_1[v13];
    *(_WORD *)(result + a3 + 2) = 15677;
    result += 4;
    *(_BYTE *)(result + a3) = 0;
  }
  else
  {
    if ( v12 == 2 )
    {
      v14 = (*(unsigned __int8 *)(v3 + a1 + 1) | ((unsigned __int64)*(unsigned __int8 *)(v3 + a1) << 8)) << 8;
      *(_BYTE *)(result + a3) = aAbcdefghijklmn_1[v14 >> 18];
      *(_BYTE *)(result + a3 + 1) = aAbcdefghijklmn_1[(v14 >> 12) & 0x3F];
      *(_BYTE *)(result + a3 + 2) = aAbcdefghijklmn_1[(v14 >> 6) & 0x3F];
      *(_BYTE *)(result + a3 + 3) = 61;
      result += 4;
    }
    *(_BYTE *)(result + a3) = 0;
  }
  return result;
}
