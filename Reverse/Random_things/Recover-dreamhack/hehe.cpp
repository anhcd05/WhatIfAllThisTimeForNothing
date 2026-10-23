


#include<stdio.h>

int main(){
	FILE *stream = fopen("encrypted", "rb");
	FILE *s = fopen("flag.png", "wb");
	
	int v5 = 0;
	
	unsigned char v6[] =
		{
		  222, 173, 190, 239
		};
	char ptr;
	while ( fread(&ptr, 1, 1, stream) == 1 )	{
	    ptr -= 19;
		ptr ^= v6[v5 % 4];
		fwrite(&ptr, 1, 1, s);
		++v5;
	}
	fclose(stream);
  	
	fclose(s);
	
	
	
	
	
}
