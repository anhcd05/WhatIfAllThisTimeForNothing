__int64 __fastcall b64_decode(char *in, unsigned __int8 *out)
{
  char v2; // al
  unsigned int v3; // esi
  char *v5; // r14
  int v6; // ebx
  __int64 v7; // rdi
  char *v8; // rax
  unsigned int v9; // eax

  v2 = *in;
  v3 = 0;
  v5 = in;
  v6 = 0;
  v7 = 0;
  if ( *in == 0 )
    return 0;
  do
  {
    if ( v2 == 61 )
      break;
    v8 = strchr(string: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", ch: v2);
    if ( v8 != nullptr )
    {
      v9 = (v3 << 6) | ((_DWORD)v8 - (unsigned int)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
      v6 += 6;
      v3 = v9;
      if ( v6 >= 8 )
      {
        v6 -= 8;
        out[v7++] = v9 >> v6;
      }
    }
    v2 = *++v5;
  }
  while ( v2 != 0 );
  return v7;
}
