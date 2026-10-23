__int64 __fastcall salsa20_xor(__int64 *a1, int *a2, __int64 a3, unsigned __int64 a4)
{
  _BYTE *v7; // r15
  unsigned __int64 v8; // rdi
  __int64 v9; // r12
  unsigned __int64 v10; // rbx
  __int64 result; // rax
  _BYTE v12[136]; // [rsp+20h] [rbp-88h] BYREF

  if ( a4 != 0 )
  {
    v7 = v12;
    v8 = 64;
    v9 = 0;
    while ( 1 )
    {
      v10 = v8 - 64;
      result = salsa20_block(a1, a2, a3: v9, a4: (__int64)v12);
      do
      {
        if ( v10 >= a4 )
          break;
        result = (unsigned __int8)v7[v10];
        *(_BYTE *)(a3 + v10++) ^= result;
      }
      while ( v10 != v8 );
      ++v9;
      v7 -= 64;
      if ( v8 >= a4 )
        break;
      v8 += 64LL;
    }
  }
  return result;
}
