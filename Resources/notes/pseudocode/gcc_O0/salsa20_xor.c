unsigned __int64 __fastcall salsa20_xor(__int64 a1, __int64 *a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 result; // rax
  _BYTE v9[72]; // [rsp+20h] [rbp-60h] BYREF
  unsigned __int64 i; // [rsp+68h] [rbp-18h]
  unsigned __int64 v11; // [rsp+70h] [rbp-10h]
  __int64 v12; // [rsp+78h] [rbp-8h]

  v12 = 0;
  v11 = 0;
  while ( 1 )
  {
    result = v11;
    if ( v11 >= a4 )
      break;
    salsa20_block(a1, a2, a3: v12, a4: (__int64)v9);
    for ( i = 0; i <= 0x3F && v11 + i < a4; ++i )
      *(_BYTE *)(i + v11 + a3) ^= v9[i];
    v11 += 64LL;
    ++v12;
  }
  return result;
}
