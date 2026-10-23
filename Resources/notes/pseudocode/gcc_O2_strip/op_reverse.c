// op_reverse = sub_2C60 (bản strip, IDA không có tên hàm)
char *__fastcall sub_2C60(char *a1, unsigned __int64 a2)
{
  char *result; // rax
  unsigned __int64 v3; // rsi
  char *v4; // rsi
  char v5; // cl
  char v6; // dl

  result = (char *)a2;
  v3 = a2 >> 1;
  if ( v3 != 0 )
  {
    result = &result[(_QWORD)a1 - 1];
    v4 = &a1[v3];
    do
    {
      v5 = *result;
      v6 = *a1++;
      --result;
      *(a1 - 1) = v5;
      result[1] = v6;
    }
    while ( a1 != v4 );
  }
  return result;
}
