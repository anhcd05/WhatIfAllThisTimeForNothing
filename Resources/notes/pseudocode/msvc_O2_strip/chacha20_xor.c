// chacha20_xor = sub_1400027B0 (bản strip, IDA không có tên hàm)
void __fastcall sub_1400027B0(__int128 *a1, int *a2, __int64 a3, unsigned __int64 a4)
{
  unsigned int v4; // r15d
  __int64 v5; // rsi
  char *v6; // rbx
  unsigned __int64 v8; // r14
  unsigned __int64 i; // r8
  unsigned __int64 v13; // rax
  __int64 v14; // rdx
  __int64 v15; // [rsp+0h] [rbp-A8h] BYREF
  char v16; // [rsp+20h] [rbp-88h] BYREF

  if ( a4 != 0 )
  {
    v4 = 0;
    v5 = 2;
    v6 = (char *)&v15 + 31;
    v8 = ((a4 - 1) >> 6) + 1;
    do
    {
      sub_140002430(a1, a2: v4, a3: a2, a4: (__int64)&v16);
      for ( i = 0; i < 0x40; i += 4LL )
      {
        v13 = v5 + i;
        if ( v5 + i - 2 >= a4 )
          break;
        *(_BYTE *)(v5 + a3 + i - 2) ^= v6[v13 - 1];
        if ( v13 - 1 >= a4 )
          break;
        v14 = v5 + a3;
        *(_BYTE *)(v5 + a3 + i - 1) ^= v6[v13];
        if ( v13 >= a4 )
          break;
        *(_BYTE *)(v14 + i) ^= v6[v13 + 1];
        if ( v13 + 1 >= a4 )
          break;
        *(_BYTE *)(v14 + i + 1) ^= v6[v13 + 2];
      }
      v6 -= 64;
      v5 += 64;
      ++v4;
      --v8;
    }
    while ( v8 != 0 );
  }
}
