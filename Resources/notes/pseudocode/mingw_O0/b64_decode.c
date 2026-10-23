__int64 __fastcall b64_decode(_BYTE *a1, __int64 a2)
{
  __int64 v2; // rax
  char *v4; // [rsp+28h] [rbp-18h]
  __int64 v5; // [rsp+30h] [rbp-10h]
  int v6; // [rsp+38h] [rbp-8h]
  unsigned int v7; // [rsp+3Ch] [rbp-4h]

  v7 = 0;
  v6 = 0;
  v5 = 0;
  while ( *a1 != 0 && *a1 != 61 )
  {
    v4 = strchr(Str: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", Val: (char)*a1);
    if ( v4 != nullptr )
    {
      v7 = (v7 << 6) | (v4 - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
      v6 += 6;
      if ( v6 > 7 )
      {
        v6 -= 8;
        v2 = v5++;
        *(_BYTE *)(a2 + v2) = v7 >> v6;
      }
    }
    ++a1;
  }
  return v5;
}
