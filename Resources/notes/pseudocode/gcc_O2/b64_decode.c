__int64 __fastcall b64_decode(_BYTE *a1, __int64 a2)
{
  int v3; // esi
  _BYTE *v4; // r14
  __int64 v5; // r12
  int v6; // r15d
  unsigned int v7; // ebx
  char *v8; // rax

  v3 = (char)*a1;
  if ( *a1 != 0 && (_BYTE)v3 != 61 )
  {
    v4 = a1;
    v5 = 0;
    v6 = 0;
    v7 = 0;
    while ( 1 )
    {
      v8 = strchr(s: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", c: v3);
      if ( v8 == nullptr )
        goto LABEL_5;
      v7 = ((_DWORD)v8 - (unsigned int)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") | (v7 << 6);
      if ( v6 + 6 > 7 )
        break;
      v3 = (char)*++v4;
      v6 += 6;
      if ( (_BYTE)v3 == 0 )
        return v5;
LABEL_6:
      if ( (_BYTE)v3 == 61 )
        return v5;
    }
    v6 -= 2;
    *(_BYTE *)(a2 + v5++) = v7 >> v6;
LABEL_5:
    v3 = (char)*++v4;
    if ( (_BYTE)v3 == 0 )
      return v5;
    goto LABEL_6;
  }
  return 0;
}
