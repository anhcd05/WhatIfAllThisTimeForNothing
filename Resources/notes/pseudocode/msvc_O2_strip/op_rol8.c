// op_rol8 = sub_140003F00 (bản strip, IDA không có tên hàm)
char *__fastcall sub_140003F00(char *a1, __int64 a2, char a3)
{
  char *result; // rax
  char v4; // r9

  for ( result = a1; a2 != 0; --a2 )
  {
    v4 = *result++;
    *(result - 1) = __ROL1__(v4, a3);
  }
  return result;
}
