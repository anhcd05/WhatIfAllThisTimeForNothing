__int64 __fastcall a85_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  _BYTE Src[5]; // [rsp+2Ah] [rbp-36h] BYREF
  unsigned int v7; // [rsp+2Fh] [rbp-31h] BYREF
  int v8; // [rsp+33h] [rbp-2Dh]
  char v9; // [rsp+37h] [rbp-29h]
  size_t Size; // [rsp+38h] [rbp-28h]
  int k; // [rsp+40h] [rbp-20h]
  unsigned int v12; // [rsp+44h] [rbp-1Ch]
  int j; // [rsp+48h] [rbp-18h]
  unsigned int v14; // [rsp+4Ch] [rbp-14h]
  unsigned __int64 i; // [rsp+50h] [rbp-10h]
  __int64 v16; // [rsp+58h] [rbp-8h]

  v16 = 0;
  for ( i = 0; a2 >= i + 4; i += 4LL )
  {
    v14 = (*(unsigned __int8 *)(i + 2 + a1) << 8)
        | (*(unsigned __int8 *)(i + 1 + a1) << 16)
        | (*(unsigned __int8 *)(a1 + i) << 24)
        | *(unsigned __int8 *)(i + 3 + a1);
    if ( v14 != 0 )
    {
      for ( j = 4; j >= 0; --j )
      {
        *((_BYTE *)&v8 + j) = v14 % 0x55 + 33;
        v14 /= 0x55u;
      }
      v4 = a3 + v16;
      *(_DWORD *)v4 = v8;
      *(_BYTE *)(v4 + 4) = v9;
      v16 += 5;
    }
    else
    {
      v3 = v16++;
      *(_BYTE *)(a3 + v3) = 122;
    }
  }
  if ( i < a2 )
  {
    v7 = 0;
    Size = a2 - i;
    memcpy_0(a1: &v7, Src: (const void *)(i + a1), Size: a2 - i);
    v12 = _byteswap_ulong(v7);
    for ( k = 4; k >= 0; --k )
    {
      Src[k] = v12 % 0x55 + 33;
      v12 /= 0x55u;
    }
    memcpy_0(a1: (void *)(a3 + v16), Src, Size: Size + 1);
    v16 += Size + 1;
  }
  *(_BYTE *)(a3 + v16) = 0;
  return v16;
}
