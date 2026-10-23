char *__fastcall op_reverse(char *a1, char *a2)
{
  char *result; // rax
  unsigned __int64 v3; // rsi
  char *v4; // rsi
  char v5; // cl
  char v6; // dl

  result = a2;
  v3 = (unsigned __int64)a2 >> 1;
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
