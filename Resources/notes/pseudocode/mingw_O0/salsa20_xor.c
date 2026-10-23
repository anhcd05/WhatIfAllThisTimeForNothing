unsigned __int64 __fastcall salsa20_xor(__int64 a1, __int64 *a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 result; // rax
  _BYTE v5[72]; // [rsp+20h] [rbp-60h] BYREF
  unsigned __int64 i; // [rsp+68h] [rbp-18h]
  unsigned __int64 v7; // [rsp+70h] [rbp-10h]
  __int64 v8; // [rsp+78h] [rbp-8h]

  v8 = 0;
  v7 = 0;
  while ( 1 )
  {
    result = v7;
    if ( v7 >= a4 )
      break;
    salsa20_block(a1, a2, a3: v8, a4: (__int64)v5);
    for ( i = 0; i <= 0x3F && v7 + i < a4; ++i )
      *(_BYTE *)(i + v7 + a3) ^= v5[i];
    v7 += 64LL;
    ++v8;
  }
  return result;
}
