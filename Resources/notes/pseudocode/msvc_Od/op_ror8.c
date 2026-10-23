void __fastcall op_ror8(unsigned __int8 *b, unsigned __int64 n, char k)
{
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  for ( i = 0; i < n; ++i )
    b[i] = (b[i] << (8 - k)) | ((int)b[i] >> k);
}
