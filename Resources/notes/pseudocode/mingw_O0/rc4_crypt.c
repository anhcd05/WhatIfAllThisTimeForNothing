unsigned __int64 __fastcall rc4_crypt(__int64 a1, unsigned __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 result; // rax
  _BYTE v5[271]; // [rsp+0h] [rbp-80h]
  char v6; // [rsp+10Fh] [rbp+8Fh]
  unsigned __int64 j; // [rsp+110h] [rbp+90h]
  int v8; // [rsp+118h] [rbp+98h]
  int i; // [rsp+11Ch] [rbp+9Ch]

  v8 = 0;
  for ( i = 0; i <= 255; ++i )
    v5[i] = i;
  for ( i = 0; i <= 255; ++i )
  {
    v8 = (unsigned __int8)(v5[i] + v8 + *(_BYTE *)(i % a2 + a1));
    v6 = v5[i];
    v5[i] = v5[v8];
    v5[v8] = v6;
  }
  i = 0;
  v8 = 0;
  for ( j = 0; ; ++j )
  {
    result = j;
    if ( j >= a4 )
      break;
    i = (unsigned __int8)(i + 1);
    v8 = (unsigned __int8)(v5[i] + v8);
    v6 = v5[i];
    v5[i] = v5[v8];
    v5[v8] = v6;
    *(_BYTE *)(a3 + j) ^= v5[(unsigned __int8)(v5[i] + v5[v8])];
  }
  return result;
}
