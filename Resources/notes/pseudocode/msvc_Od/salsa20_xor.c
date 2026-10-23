void __fastcall salsa20_xor(const unsigned int *key, unsigned int *nonce, unsigned __int8 *buf, unsigned __int64 n)
{
  unsigned __int64 i; // [rsp+20h] [rbp-78h]
  unsigned __int64 off; // [rsp+28h] [rbp-70h]
  unsigned __int64 ctr; // [rsp+30h] [rbp-68h]
  unsigned __int8 ks[64]; // [rsp+40h] [rbp-58h] BYREF

  ctr = 0;
  for ( off = 0; off < n; off += 64LL )
  {
    salsa20_block(key, nonce, counter: ctr, out: ks);
    for ( i = 0; i < 0x40 && i + off < n; ++i )
      buf[i + off] ^= ks[i];
    ++ctr;
  }
}
