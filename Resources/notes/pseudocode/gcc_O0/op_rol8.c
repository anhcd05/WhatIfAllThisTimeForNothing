unsigned __int64 __fastcall op_rol8(__int64 a1, unsigned __int64 a2, char a3)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+1Ch] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(a1 + i) = ((int)*(unsigned __int8 *)(a1 + i) >> (8 - a3)) | (*(_BYTE *)(a1 + i) << a3);
  }
  return result;
}
