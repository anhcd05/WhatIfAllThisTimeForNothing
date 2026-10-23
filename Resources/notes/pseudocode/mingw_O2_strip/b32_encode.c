// b32_encode = sub_140001740 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140001740(unsigned __int8 *a1, __int64 a2, _BYTE *a3)
{
  unsigned __int8 *v3; // rdi
  unsigned __int8 *v4; // r10
  int v5; // r9d
  unsigned __int64 v6; // rdx
  __int64 result; // rax
  __int64 v8; // rsi
  int v9; // ecx
  __int64 v10; // r9
  _BYTE *v11; // r10

  if ( a2 != 0 )
  {
    v3 = &a1[a2];
    v4 = a1;
    v5 = 0;
    v6 = 0;
    result = 0;
    do
    {
      while ( 1 )
      {
        v8 = result + 1;
        v6 = *v4 | (v6 << 8);
        v9 = v5 + 3;
        a3[result] = aAbcdefghijklmn_1[(v6 >> ((unsigned __int8)v5 + 3)) & 0x1F];
        if ( v5 + 3 <= 4 )
          break;
        v5 -= 2;
        result += 2;
        ++v4;
        a3[result - 1] = aAbcdefghijklmn_1[(v6 >> v5) & 0x1F];
        if ( v4 == v3 )
          goto LABEL_6;
      }
      v10 = result;
      ++v4;
      ++result;
      v8 = v10;
      v5 = v9;
    }
    while ( v4 != v3 );
LABEL_6:
    if ( v5 != 0 )
    {
      v11 = &a3[result];
      result = v8 + 2;
      *v11 = aAbcdefghijklmn_1[(v6 << (5 - (unsigned __int8)v5)) & 0x1F];
    }
    while ( (result & 7) != 0 )
      a3[result++] = 61;
    a3[result] = 0;
  }
  else
  {
    *a3 = 0;
    return 0;
  }
  return result;
}
