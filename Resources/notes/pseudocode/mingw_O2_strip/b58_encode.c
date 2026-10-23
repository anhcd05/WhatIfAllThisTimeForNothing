// b58_encode = sub_140001840 (bản strip, IDA không có tên hàm)
size_t __fastcall sub_140001840(__int64 a1, size_t a2, _BYTE *a3)
{
  size_t v4; // rdi
  unsigned __int8 *v5; // r8
  __int64 v6; // rsi
  unsigned __int8 *v7; // r10
  int v8; // eax
  _BYTE *v9; // rdx
  int v10; // r11d
  int v11; // r11d
  _BYTE *v12; // rax
  _BYTE *v13; // rax
  _BYTE *v14; // rdx
  __int64 v15; // rcx
  _BYTE v18[344]; // [rsp+20h] [rbp-158h] BYREF

  memset(v18, 0, 300);
  v4 = 0;
  if ( a2 == 0 )
  {
LABEL_31:
    v12 = a3;
    v4 = 0;
    goto LABEL_20;
  }
  while ( *(_BYTE *)(a1 + v4) == 0 )
  {
    if ( a2 == ++v4 )
      goto LABEL_27;
  }
  if ( v4 < a2 )
  {
    v5 = (unsigned __int8 *)(a1 + v4);
    v6 = 0;
    v7 = (unsigned __int8 *)(a2 + a1);
    while ( 1 )
    {
      v8 = *v5;
      if ( v6 != 0 )
      {
        v9 = v18;
        do
        {
          v10 = (unsigned __int8)*v9++;
          v11 = v8 + (v10 << 8);
          v8 = v11 / 58;
          *(v9 - 1) = v11 % 58;
        }
        while ( &v18[v6] != v9 );
        if ( v8 == 0 )
          goto LABEL_13;
      }
      else
      {
        while ( v8 == 0 )
        {
          if ( v7 == v5 + 1 )
          {
            if ( v4 != 0 )
              goto LABEL_27;
            goto LABEL_31;
          }
          v8 = v5[1];
          if ( v5[1] != 0 )
          {
            ++v5;
            break;
          }
          v5 += 2;
          if ( v7 == v5 )
            goto LABEL_14;
          v8 = *v5;
        }
      }
      v18[v6] = v8 % 58;
      if ( v8 / 58 != 0 )
      {
        v6 += 2;
        v18[v6 - 1] = v8 / 58;
      }
      else
      {
        ++v6;
      }
LABEL_13:
      if ( v7 == ++v5 )
      {
LABEL_14:
        if ( v4 != 0 )
          goto LABEL_15;
        v12 = a3;
        goto LABEL_16;
      }
    }
  }
LABEL_27:
  v6 = 0;
LABEL_15:
  a3 = memset(a1: a3, Val: 49, Size: v4);
  v12 = &a3[v4];
LABEL_16:
  if ( v6 != 0 )
  {
    v13 = &v18[v6];
    v14 = &a3[v4];
    do
    {
      v15 = (unsigned __int8)*--v13;
      *v14++ = a123456789abcde[v15];
    }
    while ( v18 != v13 );
    v4 += v6;
    v12 = &a3[v4];
  }
LABEL_20:
  *v12 = 0;
  return v4;
}
