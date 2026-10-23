// rot13 = sub_140004170 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004170(_BYTE *a1, __int64 a2)
{
  __int64 v2; // r9
  int v3; // r8d
  int v4; // r8d
  __int64 result; // rax
  char v6; // r8
  int v7; // r8d

  v2 = a2;
  if ( a2 != 0 )
  {
    while ( 1 )
    {
      v3 = (unsigned __int8)*a1;
      if ( (unsigned __int8)(v3 - 97) <= 0x19u )
        break;
      result = (unsigned int)(v3 - 65);
      if ( (unsigned __int8)(v3 - 65) <= 0x19u )
      {
        v7 = (char)v3 - 52;
        result = (unsigned int)(26 * (v7 / 26));
        v6 = v7 % 26 + 65;
        goto LABEL_6;
      }
LABEL_7:
      ++a1;
      if ( --v2 == 0 )
        return result;
    }
    v4 = (char)v3 - 84;
    result = (unsigned int)(26 * (v4 / 26));
    v6 = v4 % 26 + 97;
LABEL_6:
    *a1 = v6;
    goto LABEL_7;
  }
  return result;
}
