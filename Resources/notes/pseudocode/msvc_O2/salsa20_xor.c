void __fastcall salsa20_xor(
        const unsigned int *key,
        const unsigned int *nonce,
        unsigned __int8 *buf,
        unsigned __int64 n)
{
  unsigned __int64 v4; // r15
  __int64 v5; // rsi
  char *v6; // rbx
  unsigned __int64 v8; // r14
  unsigned __int64 i; // r8
  unsigned __int64 v13; // rax
  unsigned __int8 *v14; // rdx
  __int64 v15; // [rsp+0h] [rbp-A8h] BYREF
  unsigned __int8 ks[64]; // [rsp+20h] [rbp-88h] BYREF

  if ( n != 0 )
  {
    v4 = 0;
    v5 = 2;
    v6 = (char *)&v15 + 31;
    v8 = ((n - 1) >> 6) + 1;
    do
    {
      salsa20_block(key, nonce, counter: v4, out: ks);
      for ( i = 0; i < 0x40; i += 4LL )
      {
        v13 = v5 + i;
        if ( v5 + i - 2 >= n )
          break;
        buf[v5 - 2 + i] ^= v6[v13 - 1];
        if ( v13 - 1 >= n )
          break;
        v14 = &buf[v5];
        buf[v5 - 1 + i] ^= v6[v13];
        if ( v13 >= n )
          break;
        v14[i] ^= v6[v13 + 1];
        if ( v13 + 1 >= n )
          break;
        v14[i + 1] ^= v6[v13 + 2];
      }
      v6 -= 64;
      v5 += 64;
      ++v4;
      --v8;
    }
    while ( v8 != 0 );
  }
}
