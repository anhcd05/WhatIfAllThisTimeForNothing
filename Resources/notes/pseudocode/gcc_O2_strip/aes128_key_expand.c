// aes128_key_expand = sub_3310 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_3310(const __m128i *a1, __m128i *a2)
{
  __int64 v2; // rdx
  int v3; // ecx
  __int64 result; // rax

  v2 = 4;
  v3 = 1;
  *a2 = _mm_loadu_si128(a1);
  do
  {
    result = a2->m128i_u32[v2 - 1];
    if ( ((v2 * 4) & 0xF) == 0 )
    {
      result = (unsigned __int8)(v3 ^ byte_6DC0[BYTE1(result)])
             | (((unsigned __int8)byte_6DC0[BYTE2(result)]
               | (((unsigned __int8)byte_6DC0[BYTE3(result)] | ((unsigned __int8)byte_6DC0[(unsigned __int8)result] << 8)) << 8)) << 8);
      v3 = ((char)v3 >> 7) & 0x1B ^ (2 * v3);
    }
    a2->m128i_i32[v2] = _mm_cvtsi128_si32(_mm_xor_si128(_mm_cvtsi32_si128(result), _mm_cvtsi32_si128(a2[-1].m128i_u32[v2])));
    ++v2;
  }
  while ( v2 != 44 );
  return result;
}
