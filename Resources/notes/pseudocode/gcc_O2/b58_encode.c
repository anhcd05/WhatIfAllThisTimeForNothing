size_t __fastcall b58_encode(__int64 a1, size_t a2, _BYTE *a3)
{
  size_t v5; // r12
  unsigned __int8 *v6; // rsi
  unsigned __int8 *v7; // rdi
  __int64 v8; // rbp
  int v9; // eax
  _BYTE *v10; // rdx
  int v11; // r9d
  int v12; // r9d
  _BYTE *v13; // rax
  _BYTE *v14; // rax
  _BYTE *v15; // rdx
  __int64 v16; // rcx
  _BYTE v19[328]; // [rsp+2h] [rbp-148h] BYREF

  v5 = 0;
  memset(v19, 0, 300);
  if ( a2 == 0 )
  {
LABEL_31:
    v13 = a3;
    v5 = 0;
    goto LABEL_20;
  }
  while ( *(_BYTE *)(a1 + v5) == 0 )
  {
    if ( a2 == ++v5 )
      goto LABEL_27;
  }
  if ( v5 < a2 )
  {
    v6 = (unsigned __int8 *)(a1 + v5);
    v7 = (unsigned __int8 *)(a1 + a2);
    v8 = 0;
    while ( 1 )
    {
      v9 = *v6;
      if ( v8 != 0 )
      {
        v10 = v19;
        do
        {
          v11 = (unsigned __int8)*v10++;
          v12 = v9 + (v11 << 8);
          v9 = v12 / 58;
          *(v10 - 1) = v12 % 58;
        }
        while ( &v19[v8] != v10 );
        if ( v9 == 0 )
          goto LABEL_13;
      }
      else
      {
        while ( v9 == 0 )
        {
          if ( v7 == v6 + 1 )
          {
            if ( v5 != 0 )
              goto LABEL_27;
            goto LABEL_31;
          }
          v9 = v6[1];
          if ( v6[1] != 0 )
          {
            ++v6;
            break;
          }
          v6 += 2;
          if ( v7 == v6 )
            goto LABEL_14;
          v9 = *v6;
        }
      }
      v19[v8] = v9 % 58;
      if ( v9 / 58 != 0 )
      {
        v8 += 2;
        v19[v8 - 1] = v9 / 58;
      }
      else
      {
        ++v8;
      }
LABEL_13:
      if ( v7 == ++v6 )
      {
LABEL_14:
        if ( v5 != 0 )
          goto LABEL_15;
        v13 = a3;
        goto LABEL_16;
      }
    }
  }
LABEL_27:
  v8 = 0;
LABEL_15:
  a3 = memset(s: a3, c: 49, n: v5);
  v13 = &a3[v5];
LABEL_16:
  if ( v8 != 0 )
  {
    v14 = &v19[v8];
    v15 = &a3[v5];
    do
    {
      v16 = (unsigned __int8)*--v14;
      *v15++ = T_3[v16];
    }
    while ( v19 != v14 );
    v5 += v8;
    v13 = &a3[v5];
  }
LABEL_20:
  *v13 = 0;
  return v5;
}
