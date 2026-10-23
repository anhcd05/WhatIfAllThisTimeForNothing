void __fastcall rot13(_BYTE *a1, __int64 a2)
{
  _BYTE *v3; // rdx
  _BYTE *v4; // r8
  int v5; // eax

  if ( a2 != 0 )
  {
    v3 = a1;
    v4 = &a1[a2];
    do
    {
      while ( 1 )
      {
        v5 = (char)*v3;
        if ( (unsigned __int8)(*v3 - 97) > 0x19u )
          break;
        *v3 = (v5 - 84) % 0x1Au + 97;
LABEL_4:
        if ( v4 == ++v3 )
          return;
      }
      if ( (unsigned __int8)(v5 - 65) > 0x19u )
        goto LABEL_4;
      *v3++ = (v5 - 52) % 0x1Au + 65;
    }
    while ( v4 != v3 );
  }
}
