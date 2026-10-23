// b58_encode = sub_1400020B0 (bản strip, IDA không có tên hàm)
unsigned __int64 __fastcall sub_1400020B0(__int64 a1, unsigned __int64 a2, void *a3)
{
  unsigned __int64 v6; // rdi
  unsigned __int64 v7; // rsi
  unsigned __int64 v8; // rbx
  unsigned __int64 i; // r9
  int v10; // ecx
  unsigned __int64 j; // r8
  int v12; // ecx
  _BYTE v15[304]; // [rsp+20h] [rbp-158h] BYREF

  v6 = 0;
  v7 = 0;
  v8 = 0;
  sub_140007EA0(a1: v15, a2: 0, a3: 300);
  if ( a2 != 0 )
  {
    do
    {
      if ( *(_BYTE *)(v7 + a1) != 0 )
        break;
      ++v7;
    }
    while ( v7 < a2 );
  }
  for ( i = v7; i < a2; ++i )
  {
    v10 = *(unsigned __int8 *)(i + a1);
    for ( j = 0; j < v8; v10 = v12 / 58 )
    {
      v12 = ((unsigned __int8)v15[j] << 8) + v10;
      v15[j++] = v12 % 58;
    }
    for ( ; v10 != 0; v10 /= 58 )
      v15[v8++] = v10 % 58;
  }
  if ( v7 != 0 )
  {
    memset(a3, 49, v7);
    v6 = v7;
  }
  for ( ; v8 != 0; --v8 )
    *((_BYTE *)a3 + v6++) = a123456789abcde[(unsigned __int8)v15[v8 - 1]];
  *((_BYTE *)a3 + v6) = 0;
  return v6;
}
