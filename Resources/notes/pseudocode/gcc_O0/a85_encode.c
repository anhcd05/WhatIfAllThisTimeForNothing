__int64 __fastcall a85_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  _BYTE src[5]; // [rsp+2Ah] [rbp-36h] BYREF
  unsigned int dest; // [rsp+2Fh] [rbp-31h] BYREF
  int v9; // [rsp+33h] [rbp-2Dh]
  char v10; // [rsp+37h] [rbp-29h]
  size_t n; // [rsp+38h] [rbp-28h]
  int k; // [rsp+40h] [rbp-20h]
  unsigned int v13; // [rsp+44h] [rbp-1Ch]
  int j; // [rsp+48h] [rbp-18h]
  unsigned int v15; // [rsp+4Ch] [rbp-14h]
  unsigned __int64 i; // [rsp+50h] [rbp-10h]
  __int64 v17; // [rsp+58h] [rbp-8h]

  v17 = 0;
  for ( i = 0; a2 >= i + 4; i += 4LL )
  {
    v15 = (*(unsigned __int8 *)(i + 2 + a1) << 8)
        | (*(unsigned __int8 *)(i + 1 + a1) << 16)
        | (*(unsigned __int8 *)(a1 + i) << 24)
        | *(unsigned __int8 *)(i + 3 + a1);
    if ( v15 != 0 )
    {
      for ( j = 4; j >= 0; --j )
      {
        *((_BYTE *)&v9 + j) = v15 % 0x55 + 33;
        v15 /= 0x55u;
      }
      v4 = a3 + v17;
      *(_DWORD *)v4 = v9;
      *(_BYTE *)(v4 + 4) = v10;
      v17 += 5;
    }
    else
    {
      v3 = v17++;
      *(_BYTE *)(a3 + v3) = 122;
    }
  }
  if ( i < a2 )
  {
    dest = 0;
    n = a2 - i;
    memcpy(&dest, src: (const void *)(a1 + i), n: a2 - i);
    v13 = _byteswap_ulong(dest);
    for ( k = 4; k >= 0; --k )
    {
      src[k] = v13 % 0x55 + 33;
      v13 /= 0x55u;
    }
    memcpy(dest: (void *)(v17 + a3), src, n: n + 1);
    v17 += n + 1;
  }
  *(_BYTE *)(a3 + v17) = 0;
  return v17;
}
