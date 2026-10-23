// b32_encode = sub_2250 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2250(unsigned __int8 *a1, __int64 a2, _BYTE *a3)
{
  unsigned __int64 v4; // rdx
  unsigned __int8 *v5; // rbx
  __int64 result; // rax
  int v7; // esi
  __int64 v8; // r11
  int v9; // ecx
  __int64 v10; // rsi
  _BYTE *v11; // rdi

  if ( a2 != 0 )
  {
    v4 = 0;
    v5 = &a1[a2];
    result = 0;
    v7 = 0;
    do
    {
      while ( 1 )
      {
        v8 = result + 1;
        v4 = *a1 | (v4 << 8);
        v9 = v7 + 3;
        a3[result] = aAbcdefghijklmn_1[(v4 >> ((unsigned __int8)v7 + 3)) & 0x1F];
        if ( v7 + 3 <= 4 )
          break;
        v7 -= 2;
        result += 2;
        ++a1;
        a3[result - 1] = aAbcdefghijklmn_1[(v4 >> v7) & 0x1F];
        if ( a1 == v5 )
          goto LABEL_6;
      }
      v10 = result;
      ++a1;
      ++result;
      v8 = v10;
      v7 = v9;
    }
    while ( a1 != v5 );
LABEL_6:
    if ( v7 != 0 )
    {
      v11 = &a3[result];
      result = v8 + 2;
      *v11 = aAbcdefghijklmn_1[(v4 << (5 - (unsigned __int8)v7)) & 0x1F];
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
