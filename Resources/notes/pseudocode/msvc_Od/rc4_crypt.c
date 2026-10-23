void __fastcall rc4_crypt(const unsigned __int8 *key, unsigned __int64 kl, unsigned __int8 *buf, unsigned __int64 n)
{
  unsigned __int64 v4; // rdx
  int i; // [rsp+0h] [rbp-138h]
  int ia; // [rsp+0h] [rbp-138h]
  int ib; // [rsp+0h] [rbp-138h]
  unsigned __int8 t; // [rsp+4h] [rbp-134h]
  unsigned __int8 ta; // [rsp+4h] [rbp-134h]
  int j; // [rsp+8h] [rbp-130h]
  int ja; // [rsp+8h] [rbp-130h]
  unsigned __int64 k; // [rsp+10h] [rbp-128h]
  char v13; // [rsp+18h] [rbp-120h]
  unsigned __int8 S[256]; // [rsp+20h] [rbp-118h]

  LOBYTE(j) = 0;
  for ( i = 0; i < 256; ++i )
    S[i] = i;
  for ( ia = 0; ia < 256; ++ia )
  {
    v13 = S[ia] + j;
    v4 = ia % kl;
    j = (unsigned __int8)(key[v4] + v13);
    t = S[ia];
    S[ia] = S[(unsigned __int8)(key[v4] + v13)];
    S[j] = t;
  }
  LOBYTE(ib) = 0;
  LOBYTE(ja) = 0;
  for ( k = 0; k < n; ++k )
  {
    ib = (unsigned __int8)(ib + 1);
    ja = (unsigned __int8)(S[ib] + ja);
    ta = S[ib];
    S[ib] = S[ja];
    S[ja] = ta;
    buf[k] ^= S[(unsigned __int8)(S[ja] + S[ib])];
  }
}
