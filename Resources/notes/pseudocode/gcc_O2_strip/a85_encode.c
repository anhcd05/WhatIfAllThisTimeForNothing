// a85_encode = sub_2510 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2510(__int64 a1, unsigned __int64 a2, _BYTE *a3)
{
  __int64 v3; // rbx
  unsigned __int64 i; // rcx
  unsigned __int64 v5; // rax
  _BYTE *v6; // r11
  unsigned int v7; // eax
  unsigned int *p_src; // rbp
  _BYTE *v9; // rbp
  unsigned __int64 v12; // r12
  unsigned int *v13; // rcx
  unsigned __int32 v14; // eax
  unsigned int dest; // [rsp+4h] [rbp-34h] BYREF
  int src; // [rsp+Bh] [rbp-2Dh] BYREF
  char v17; // [rsp+Fh] [rbp-29h]

  if ( a2 > 3 )
  {
    v3 = 0;
    for ( i = 4; ; i = v5 )
    {
      v6 = &a3[v3];
      v7 = _byteswap_ulong(*(_DWORD *)(a1 + i - 4));
      if ( v7 != 0 )
      {
        p_src = (unsigned int *)&src;
        do
        {
          p_src = (unsigned int *)((char *)p_src - 1);
          *((_BYTE *)p_src + 5) = v7 % 0x55 + 33;
          v7 /= 0x55u;
        }
        while ( p_src != (unsigned int *)((char *)&dest + 2) );
        v3 += 5;
        *(_DWORD *)v6 = src;
        v6[4] = v17;
        v5 = i + 4;
        if ( a2 < i + 4 )
        {
LABEL_9:
          v9 = &a3[v3];
          goto LABEL_10;
        }
      }
      else
      {
        v5 = i + 4;
        *v6 = 122;
        ++v3;
        if ( a2 < i + 4 )
          goto LABEL_9;
      }
    }
  }
  v9 = a3;
  i = 0;
  v3 = 0;
LABEL_10:
  if ( i < a2 )
  {
    dest = 0;
    v12 = a2 - i;
    memcpy(&dest, src: (const void *)(a1 + i), n: a2 - i);
    v13 = (unsigned int *)&src;
    v14 = _byteswap_ulong(dest);
    do
    {
      v13 = (unsigned int *)((char *)v13 - 1);
      *((_BYTE *)v13 + 5) = v14 % 0x55 + 33;
      v14 /= 0x55u;
    }
    while ( (unsigned int *)((char *)&dest + 2) != v13 );
    memcpy(dest: v9, &src, n: v12 + 1);
    v3 += v12 + 1;
    v9 = &a3[v3];
  }
  *v9 = 0;
  return v3;
}
