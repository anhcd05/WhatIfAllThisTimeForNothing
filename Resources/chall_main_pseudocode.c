// IDA Free 9.4 (Hex-Rays cloud decompiler) - chall (ELF64 PIE, stripped), main @ 0x1209
// sha256(chall) = 512d252cc50bcf13bae1c1a9f72d5ca9ffa326f0ebdb5a230d64a838133fba92
// Transcribed from the IDA Pseudocode-A window screenshot.

int64 __fastcall main(int a1, char **a2, char **a3)
{
  char ptr; // [rsp+Bh] [rbp-25h] BYREF
  int v5; // [rsp+Ch] [rbp-24h]
  _BYTE *v6; // [rsp+10h] [rbp-20h]
  FILE *stream; // [rsp+18h] [rbp-18h]
  FILE *s; // [rsp+20h] [rbp-10h]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v6 = &unk_2004;
  stream = fopen(filename: "flag.png", modes: "rb");
  if ( stream == nullptr )
  {
    puts(s: "fopen() error");
    exit(status: 1);
  }
  s = fopen(filename: "encrypted", modes: "wb");
  if ( s == nullptr )
  {
    puts(s: "fopen() error");
    fclose(stream);
    exit(status: 1);
  }
  v5 = 0;
  while ( fread(&ptr, size: 1u, n: 1u, stream) == 1 )
  {
    ptr ^= v6[v5 % 4];
    ptr += 19;
    fwrite(&ptr, size: 1u, n: 1u, s);
    ++v5;
  }
  fclose(stream);
  fclose(stream: s);
  return 0;
}
