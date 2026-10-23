

#include<stdio.h>
#include<string.h>

int sub_1289(__int64 a1, unsigned __int64 a2, unsigned __int64 a3){
  __int64 v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 i; // [rsp+28h] [rbp-8h]

  v4 = 1;
  // a3 = v11, a2 = v10, a1 = stream 
  for ( i = 0; i < a2; ++i )
    v4 = a1 * v4 % a3;
  // tuong duong pow(a1, a2, a3) trong python  
    
  return v4;
}



int main(){

//  int i; // [rsp+Ch] [rbp-174h]
//  __int64 v5; // [rsp+18h] [rbp-168h] BYREF
//  unsigned __int64 v6; // [rsp+20h] [rbp-160h] BYREF
//  __int64 ptr; // [rsp+28h] [rbp-158h] BYREF
//  __int64 v8; // [rsp+30h] [rbp-150h]
//  __int64 v9; // [rsp+38h] [rbp-148h]
//  unsigned __int64 v10; // [rsp+40h] [rbp-140h]
//  unsigned __int64 v11; // [rsp+48h] [rbp-138h]
//  FILE *stream; // [rsp+50h] [rbp-130h]
//  unsigned __int64 v13; // [rsp+58h] [rbp-128h]
//  char s[8]; // [rsp+60h] [rbp-120h] BYREF
//
//  v46 = __readfsqword(0x28u);
//  v10 = 0;
//  stream = fopen(filename: "n.txt", modes: "r");
//  __isoc99_fscanf(a1: stream, a2: "%llu %llu", &v5, &v6);
//  fclose(stream);
//  while ( v10 <= 0xFCFCFCFC )
//  {
//    v8 = sub_12FE(a1: v5);
//    v9 = sub_12FE(a1: v8 + 128);
//    v10 = v9 * v8;
//  }
//  printf(format: "n1 = %llu\n", v10);
//  v11 = v6;
//  v13 = (v8 - 1) * (v9 - 1);
//  while ( v11 < v13 && sub_1249(a1: v11, a2: v13) != 1 )
//    ++v11;
//  printf(format: "n2 = %llu\n", v11);
//  *(_QWORD *)s = 0;
	FILE *stream;
	char s[8]; 
  stream = fopen("out.bin", "rb");
  fscanf(stream, "%255s", s);
  fclose(stream);

  stream = fopen("flag.txt", "wb");
  int v10 = 4271010253;
  int v11 = 201326609;

  for ( int i = 0; i < strlen(s) >> 2; ++i )
  {
    __int64 ptr = sub_1289(*(unsigned int *)&s[4 * i], v11, v10);
    fwrite(&ptr, 8, 1, stream);
  }
  fclose(stream);
  return 0;
}
