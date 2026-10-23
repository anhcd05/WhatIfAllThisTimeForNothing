// b64_decode = sub_140002220 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002220(_BYTE *a1, __int64 a2)
{
  char v2; // al
  unsigned int v3; // esi
  _BYTE *v5; // r14
  int v6; // ebx
  __int64 v7; // rdi
  char *v8; // rax
  unsigned int v9; // eax

  v2 = *a1;
  v3 = 0;
  v5 = a1;
  v6 = 0;
  v7 = 0;
  if ( *a1 == 0 )
    return 0;
  do
  {
    if ( v2 == 61 )
      break;
    v8 = strchr(Str: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", Val: v2);
    if ( v8 != nullptr )
    {
      v9 = (v3 << 6) | ((_DWORD)v8 - (unsigned int)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
      v6 += 6;
      v3 = v9;
      if ( v6 >= 8 )
      {
        v6 -= 8;
        *(_BYTE *)(v7 + a2) = v9 >> v6;
        ++v7;
      }
    }
    v2 = *++v5;
  }
  while ( v2 != 0 );
  return v7;
}
