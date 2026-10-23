// op_reverse = sub_140002270 (bản strip, IDA không có tên hàm)
void __fastcall sub_140002270(char *a1, unsigned __int64 a2)
{
  char *v2; // rax
  char *v3; // r9
  char v4; // r8
  char v5; // dl

  if ( a2 >> 1 != 0 )
  {
    v2 = &a1[a2 - 1];
    v3 = &a1[a2 >> 1];
    do
    {
      v4 = *v2;
      v5 = *a1++;
      --v2;
      *(a1 - 1) = v4;
      v2[1] = v5;
    }
    while ( a1 != v3 );
  }
}
