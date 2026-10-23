// xtea_decrypt = sub_140005DE0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140005DE0(unsigned int *a1, __int64 a2)
{
  unsigned int v2; // r10d
  unsigned int v3; // r11d
  __int64 result; // rax
  unsigned __int64 v5; // r9
  __int64 i; // rsi
  unsigned int v9; // ecx
  unsigned int v10; // r11d
  unsigned int v11; // eax
  unsigned int v12; // r10d
  int v13; // edx
  unsigned int v14; // eax
  unsigned int v15; // r10d
  int v16; // edx
  unsigned int v17; // eax
  unsigned int v18; // r10d
  unsigned int v19; // ecx
  unsigned int v20; // eax
  unsigned int v21; // r10d
  int v22; // edx
  unsigned int v23; // eax
  unsigned int v24; // r10d
  int v25; // edx
  unsigned int v26; // eax
  unsigned int v27; // r10d
  unsigned int v28; // ecx
  unsigned int v29; // eax
  unsigned int v30; // r10d
  int v31; // edx
  unsigned int v32; // eax
  unsigned int v33; // r10d
  int v34; // edx
  unsigned int v35; // eax
  unsigned int v36; // r10d
  unsigned int v37; // ecx
  unsigned int v38; // eax
  unsigned int v39; // r10d
  int v40; // edx
  unsigned int v41; // eax
  unsigned int v42; // r10d
  int v43; // edx
  unsigned int v44; // eax
  unsigned int v45; // r10d
  unsigned int v46; // eax
  unsigned int v47; // r10d
  int v48; // edx
  unsigned int v49; // eax
  unsigned int v50; // r10d
  int v51; // edx
  unsigned int v52; // eax
  unsigned int v53; // r10d

  v2 = *a1;
  v3 = -957401312;
  LODWORD(result) = a1[1];
  v5 = 3337565984LL;
  for ( i = 2; i != 0; --i )
  {
    v9 = v3 + *(_DWORD *)(a2 + 4 * ((v5 >> 11) & 3));
    v10 = v3 + 1640531527;
    v11 = result - (v9 ^ (v2 + ((16 * v2) ^ (v2 >> 5))));
    v12 = v2 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v11 + ((16 * v11) ^ (v11 >> 5))));
    v13 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v12 + ((16 * v12) ^ (v12 >> 5)));
    v10 += 1640531527;
    v14 = v11 - v13;
    v15 = v12 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v14 + ((16 * v14) ^ (v14 >> 5))));
    v16 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v15 + ((16 * v15) ^ (v15 >> 5)));
    v10 += 1640531527;
    v17 = v14 - v16;
    v18 = v15 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v17 + ((16 * v17) ^ (v17 >> 5))));
    v19 = v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3));
    v10 += 1640531527;
    v20 = v17 - (v19 ^ (v18 + ((16 * v18) ^ (v18 >> 5))));
    v21 = v18 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v20 + ((16 * v20) ^ (v20 >> 5))));
    v22 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v21 + ((16 * v21) ^ (v21 >> 5)));
    v10 += 1640531527;
    v23 = v20 - v22;
    v24 = v21 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v23 + ((16 * v23) ^ (v23 >> 5))));
    v25 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v24 + ((16 * v24) ^ (v24 >> 5)));
    v10 += 1640531527;
    v26 = v23 - v25;
    v27 = v24 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v26 + ((16 * v26) ^ (v26 >> 5))));
    v28 = v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3));
    v10 += 1640531527;
    v29 = v26 - (v28 ^ (v27 + ((16 * v27) ^ (v27 >> 5))));
    v30 = v27 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v29 + ((16 * v29) ^ (v29 >> 5))));
    v31 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v30 + ((16 * v30) ^ (v30 >> 5)));
    v10 += 1640531527;
    v32 = v29 - v31;
    v33 = v30 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v32 + ((16 * v32) ^ (v32 >> 5))));
    v34 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v33 + ((16 * v33) ^ (v33 >> 5)));
    v10 += 1640531527;
    v35 = v32 - v34;
    v36 = v33 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v35 + ((16 * v35) ^ (v35 >> 5))));
    v37 = v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3));
    v10 += 1640531527;
    v38 = v35 - (v37 ^ (v36 + ((16 * v36) ^ (v36 >> 5))));
    v39 = v36 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v38 + ((16 * v38) ^ (v38 >> 5))));
    v40 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v39 + ((16 * v39) ^ (v39 >> 5)));
    v10 += 1640531527;
    v41 = v38 - v40;
    v42 = v39 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v41 + ((16 * v41) ^ (v41 >> 5))));
    v43 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v42 + ((16 * v42) ^ (v42 >> 5)));
    v10 += 1640531527;
    v44 = v41 - v43;
    v45 = v42 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v44 + ((16 * v44) ^ (v44 >> 5))));
    v46 = v44 - ((v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v45 + ((16 * v45) ^ (v45 >> 5))));
    v10 += 1640531527;
    v47 = v45 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v46 + ((16 * v46) ^ (v46 >> 5))));
    v48 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v47 + ((16 * v47) ^ (v47 >> 5)));
    v10 += 1640531527;
    v49 = v46 - v48;
    v50 = v47 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v49 + ((16 * v49) ^ (v49 >> 5))));
    v51 = (v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v50 + ((16 * v50) ^ (v50 >> 5)));
    v10 += 1640531527;
    v52 = v49 - v51;
    v53 = v50 - ((v10 + *(_DWORD *)(a2 + 4LL * (v10 & 3))) ^ (v52 + ((16 * v52) ^ (v52 >> 5))));
    result = v52 - ((v10 + *(_DWORD *)(a2 + 4LL * ((v10 >> 11) & 3))) ^ (v53 + ((16 * v53) ^ (v53 >> 5))));
    v3 = v10 + 1640531527;
    v5 = v3;
    v2 = v53 - ((v3 + *(_DWORD *)(a2 + 4LL * (v3 & 3))) ^ (result + ((16 * result) ^ ((unsigned int)result >> 5))));
  }
  *a1 = v2;
  a1[1] = result;
  return result;
}
