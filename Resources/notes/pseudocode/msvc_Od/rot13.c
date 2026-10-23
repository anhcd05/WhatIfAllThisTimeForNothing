void __fastcall rot13(char *s, unsigned __int64 n)
{
  char c; // [rsp+0h] [rbp-18h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  for ( i = 0; i < n; ++i )
  {
    c = s[i];
    if ( c < 97 || c > 122 )
    {
      if ( c >= 65 && c <= 90 )
        s[i] = (c - 52) % 26 + 65;
    }
    else
    {
      s[i] = (c - 84) % 26 + 97;
    }
  }
}
