__int64 __fastcall mix_chain(_BYTE *a1, __int64 a2)
{
  _BYTE *v2; // rdx
  int v3; // r8d
  int v4; // r9d
  int v5; // eax
  __int64 result; // rax

  if ( a2 != 0 )
  {
    v2 = &a1[a2];
    v3 = 66;
    v4 = 90 - (_DWORD)a1;
    do
    {
      v5 = v4 + (_DWORD)a1;
      LOBYTE(v5) = *a1 ^ (v4 + (_BYTE)a1);
      ++a1;
      LOBYTE(v5) = __ROL1__(v5, 3);
      result = (unsigned int)(v5 + 19);
      v3 ^= result;
      *(a1 - 1) = v3;
    }
    while ( a1 != v2 );
  }
  return result;
}
