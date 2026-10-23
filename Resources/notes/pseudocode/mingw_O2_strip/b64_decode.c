// b64_decode = sub_1400016A0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400016A0(_BYTE *a1, __int64 a2)
{
  __int64 v2; // rdi
  int v4; // edx
  _BYTE *v5; // r12
  int v6; // r13d
  unsigned int v7; // ebx
  char *v8; // rax

  v2 = 0;
  v4 = (char)*a1;
  v5 = a1;
  if ( *a1 != 0 && (_BYTE)v4 != 61 )
  {
    v6 = 0;
    v7 = 0;
    while ( 1 )
    {
      v8 = strchr(Str: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", Val: v4);
      if ( v8 == nullptr )
        goto LABEL_5;
      v7 = ((_DWORD)v8 - (unsigned int)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") | (v7 << 6);
      if ( v6 + 6 > 7 )
        break;
      v4 = (char)*++v5;
      v6 += 6;
      if ( (_BYTE)v4 == 0 )
        return v2;
LABEL_6:
      if ( (_BYTE)v4 == 61 )
        return v2;
    }
    v6 -= 2;
    *(_BYTE *)(a2 + v2++) = v7 >> v6;
LABEL_5:
    v4 = (char)*++v5;
    if ( (_BYTE)v4 == 0 )
      return v2;
    goto LABEL_6;
  }
  return v2;
}
