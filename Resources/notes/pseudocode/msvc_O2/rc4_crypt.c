void __fastcall rc4_crypt(const unsigned __int8 *key, unsigned __int64 kl, unsigned __int8 *buf, unsigned __int64 n)
{
  unsigned __int8 v4; // bl
  unsigned __int8 *v5; // r10
  __int64 v6; // rsi
  int v7; // eax
  __int64 v10; // r11
  unsigned __int64 v11; // r9
  unsigned __int8 v12; // r8
  __int64 v13; // r8
  unsigned __int8 v14; // dl
  unsigned __int8 S[256]; // [rsp+0h] [rbp-138h] BYREF

  v4 = 0;
  v5 = S;
  LOBYTE(v6) = 0;
  v7 = 0;
  v10 = 256;
  do
    *v5++ = v7++;
  while ( v7 < 256 );
  v11 = 0;
  do
  {
    v12 = S[v11];
    v6 = (unsigned __int8)(v12 + v6 + key[v11 % kl]);
    S[v11++] = S[v6];
    S[v6] = v12;
    --v10;
  }
  while ( v10 != 0 );
  for ( LOBYTE(v13) = 0; n != 0; --n )
  {
    ++buf;
    v14 = S[++v4];
    v13 = (unsigned __int8)(v13 + v14);
    S[v4] = S[v13];
    S[v13] = v14;
    *(buf - 1) ^= S[(unsigned __int8)(S[v4] + v14)];
  }
}
