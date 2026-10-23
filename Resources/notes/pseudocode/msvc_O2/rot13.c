void __fastcall rot13(char *s, unsigned __int64 n)
{
  unsigned __int64 v2; // r9
  char v3; // r8
  char v4; // r8

  v2 = n;
  if ( n != 0 )
  {
    while ( 1 )
    {
      v3 = *s;
      if ( (unsigned __int8)(*s - 97) <= 0x19u )
        break;
      if ( (unsigned __int8)(v3 - 65) <= 0x19u )
      {
        v4 = (v3 - 52) % 26 + 65;
        goto LABEL_6;
      }
LABEL_7:
      ++s;
      if ( --v2 == 0 )
        return;
    }
    v4 = (v3 - 84) % 26 + 97;
LABEL_6:
    *s = v4;
    goto LABEL_7;
  }
}
