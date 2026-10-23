void __fastcall rot13(_BYTE *a1, __int64 a2)
{
  _BYTE *v2; // rdx
  _BYTE *v3; // rsi
  int v4; // eax

  if ( a2 != 0 )
  {
    v2 = a1;
    v3 = &a1[a2];
    do
    {
      while ( 1 )
      {
        v4 = (char)*v2;
        if ( (unsigned __int8)(*v2 - 97) > 0x19u )
          break;
        *v2 = (v4 - 84) % 0x1Au + 97;
LABEL_4:
        if ( v3 == ++v2 )
          return;
      }
      if ( (unsigned __int8)(v4 - 65) > 0x19u )
        goto LABEL_4;
      *v2++ = (v4 - 52) % 0x1Au + 65;
    }
    while ( v3 != v2 );
  }
}
