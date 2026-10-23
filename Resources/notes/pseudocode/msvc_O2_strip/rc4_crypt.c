// rc4_crypt = sub_140004070 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004070(__int64 a1, unsigned __int64 a2, __int64 a3, __int64 a4)
{
  unsigned __int8 v4; // bl
  _BYTE *v5; // r10
  __int64 v6; // rsi
  int v7; // eax
  __int64 v10; // r11
  unsigned __int64 v11; // r9
  char v12; // r8
  __int64 result; // rax
  __int64 v14; // r8
  char v15; // dl
  _BYTE v16[256]; // [rsp+0h] [rbp-138h] BYREF

  v4 = 0;
  v5 = v16;
  LOBYTE(v6) = 0;
  v7 = 0;
  v10 = 256;
  do
    *v5++ = v7++;
  while ( v7 < 256 );
  v11 = 0;
  do
  {
    v12 = v16[v11];
    v6 = (unsigned __int8)(v12 + v6 + *(_BYTE *)(v11 % a2 + a1));
    result = (unsigned __int8)v16[v6];
    v16[v11++] = result;
    v16[v6] = v12;
    --v10;
  }
  while ( v10 != 0 );
  for ( LOBYTE(v14) = 0; a4 != 0; --a4 )
  {
    ++a3;
    v15 = v16[++v4];
    v14 = (unsigned __int8)(v14 + v15);
    v16[v4] = v16[v14];
    v16[v14] = v15;
    result = (unsigned __int8)(v16[v4] + v15);
    *(_BYTE *)(a3 - 1) ^= v16[result];
  }
  return result;
}
