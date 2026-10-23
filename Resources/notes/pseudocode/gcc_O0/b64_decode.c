__int64 __fastcall b64_decode(_BYTE *a1, __int64 a2)
{
  __int64 v2; // rax
  char *v6; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  int v8; // [rsp+28h] [rbp-8h]
  unsigned int v9; // [rsp+2Ch] [rbp-4h]

  v9 = 0;
  v8 = 0;
  v7 = 0;
  while ( *a1 != 0 && *a1 != 61 )
  {
    v6 = strchr(s: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", c: (char)*a1);
    if ( v6 != nullptr )
    {
      v9 = (v9 << 6) | (v6 - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
      v8 += 6;
      if ( v8 > 7 )
      {
        v8 -= 8;
        v2 = v7++;
        *(_BYTE *)(a2 + v2) = v9 >> v8;
      }
    }
    ++a1;
  }
  return v7;
}
