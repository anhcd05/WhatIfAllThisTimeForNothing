void __fastcall op_rol8(unsigned __int8 *b, unsigned __int64 n, char k)
{
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  for ( i = 0; i < n; ++i )
    b[i] = ((int)b[i] >> (8 - k)) | (b[i] << k);
}
