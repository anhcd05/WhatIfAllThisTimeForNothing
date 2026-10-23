// a85_encode = sub_140001A60 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140001A60(__int64 a1, unsigned __int64 a2, _BYTE *a3)
{
  __int64 v5; // rbx
  unsigned __int64 i; // rcx
  unsigned __int64 v7; // rax
  _BYTE *v8; // rdi
  unsigned int v9; // eax
  unsigned int *p_Src; // rbp
  _BYTE *v11; // rbp
  unsigned __int64 v13; // rdi
  unsigned int *v14; // rcx
  unsigned __int32 v15; // eax
  unsigned int v16; // [rsp+24h] [rbp-34h] BYREF
  int Src; // [rsp+2Bh] [rbp-2Dh] BYREF
  char v18; // [rsp+2Fh] [rbp-29h]

  if ( a2 > 3 )
  {
    v5 = 0;
    for ( i = 4; ; i = v7 )
    {
      v8 = &a3[v5];
      v9 = _byteswap_ulong(*(_DWORD *)(a1 + i - 4));
      if ( v9 != 0 )
      {
        p_Src = (unsigned int *)&Src;
        do
        {
          p_Src = (unsigned int *)((char *)p_Src - 1);
          *((_BYTE *)p_Src + 5) = v9 % 0x55 + 33;
          v9 /= 0x55u;
        }
        while ( p_Src != (unsigned int *)((char *)&v16 + 2) );
        v5 += 5;
        *(_DWORD *)v8 = Src;
        v8[4] = v18;
        v7 = i + 4;
        if ( a2 < i + 4 )
        {
LABEL_9:
          v11 = &a3[v5];
          goto LABEL_10;
        }
      }
      else
      {
        v7 = i + 4;
        *v8 = 122;
        ++v5;
        if ( a2 < i + 4 )
          goto LABEL_9;
      }
    }
  }
  v11 = a3;
  i = 0;
  v5 = 0;
LABEL_10:
  if ( i < a2 )
  {
    v16 = 0;
    v13 = a2 - i;
    memcpy(a1: &v16, Src: (const void *)(a1 + i), Size: a2 - i);
    v14 = (unsigned int *)&Src;
    v15 = _byteswap_ulong(v16);
    do
    {
      v14 = (unsigned int *)((char *)v14 - 1);
      *((_BYTE *)v14 + 5) = v15 % 0x55 + 33;
      v15 /= 0x55u;
    }
    while ( (unsigned int *)((char *)&v16 + 2) != v14 );
    memcpy(a1: v11, &Src, Size: v13 + 1);
    v5 += v13 + 1;
    v11 = &a3[v5];
  }
  *v11 = 0;
  return v5;
}
