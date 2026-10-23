// salsa20_xor = sub_4020 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_4020(__int64 *a1, int *a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 v4; // r15
  __int64 v6; // r12
  _BYTE *v8; // r13
  unsigned __int64 v9; // rbx
  __int64 result; // rax
  _BYTE v13[120]; // [rsp+18h] [rbp-78h] BYREF

  if ( a4 != 0 )
  {
    v4 = 64;
    v6 = 0;
    v8 = v13;
    while ( 1 )
    {
      v9 = v4 - 64;
      result = sub_3D40(a1, a2, a3: v6, a4: (__int64)v13);
      do
      {
        if ( v9 >= a4 )
          break;
        result = (unsigned __int8)v8[v9];
        *(_BYTE *)(a3 + v9++) ^= result;
      }
      while ( v9 != v4 );
      ++v6;
      v8 -= 64;
      if ( v4 >= a4 )
        break;
      v4 += 64LL;
    }
  }
  return result;
}
