void __fastcall xtea_encrypt(unsigned int *v, const unsigned int *k)
{
  unsigned int v2; // r9d
  unsigned int v3; // r10d
  unsigned int v4; // eax
  char v7; // si
  __int64 i; // rdi
  unsigned int v9; // ecx
  unsigned int v10; // r10d
  unsigned int v11; // r9d
  unsigned int v12; // eax
  unsigned int v13; // edx
  unsigned int v14; // r9d
  unsigned int v15; // eax
  unsigned int v16; // edx
  unsigned int v17; // r9d
  unsigned int v18; // eax
  unsigned int v19; // ecx
  unsigned int v20; // r9d
  unsigned int v21; // eax
  unsigned int v22; // edx
  unsigned int v23; // r9d
  unsigned int v24; // eax
  unsigned int v25; // edx
  unsigned int v26; // r9d
  unsigned int v27; // eax
  unsigned int v28; // ecx
  unsigned int v29; // r9d
  unsigned int v30; // eax
  unsigned int v31; // edx
  unsigned int v32; // r9d
  unsigned int v33; // eax
  unsigned int v34; // edx
  unsigned int v35; // r9d
  unsigned int v36; // eax
  unsigned int v37; // edx
  unsigned int v38; // r9d
  unsigned int v39; // eax
  unsigned int v40; // edx
  unsigned int v41; // r9d
  unsigned int v42; // eax
  unsigned int v43; // edx
  unsigned int v44; // r9d
  unsigned int v45; // eax
  unsigned int v46; // r9d
  unsigned int v47; // eax
  unsigned int v48; // edx
  unsigned int v49; // r9d
  unsigned int v50; // eax
  unsigned int v51; // edx
  unsigned int v52; // r9d
  unsigned int v53; // eax
  unsigned int v54; // edx

  v2 = *v;
  v3 = 0;
  v4 = v[1];
  v7 = 0;
  for ( i = 2; i != 0; --i )
  {
    v9 = v3 + k[v7 & 3];
    v10 = v3 - 1640531527;
    v11 = (v9 ^ (v4 + ((16 * v4) ^ (v4 >> 5)))) + v2;
    v12 = ((v10 + k[(v10 >> 11) & 3]) ^ (v11 + ((16 * v11) ^ (v11 >> 5)))) + v4;
    v13 = (v10 + k[v10 & 3]) ^ (v12 + ((16 * v12) ^ (v12 >> 5)));
    v10 -= 1640531527;
    v14 = v13 + v11;
    v15 = ((v10 + k[(v10 >> 11) & 3]) ^ (v14 + ((16 * v14) ^ (v14 >> 5)))) + v12;
    v16 = (v10 + k[v10 & 3]) ^ (v15 + ((16 * v15) ^ (v15 >> 5)));
    v10 -= 1640531527;
    v17 = v16 + v14;
    v18 = ((v10 + k[(v10 >> 11) & 3]) ^ (v17 + ((16 * v17) ^ (v17 >> 5)))) + v15;
    v19 = v10 + k[v10 & 3];
    v10 -= 1640531527;
    v20 = (v19 ^ (v18 + ((16 * v18) ^ (v18 >> 5)))) + v17;
    v21 = ((v10 + k[(v10 >> 11) & 3]) ^ (v20 + ((16 * v20) ^ (v20 >> 5)))) + v18;
    v22 = (v10 + k[v10 & 3]) ^ (v21 + ((16 * v21) ^ (v21 >> 5)));
    v10 -= 1640531527;
    v23 = v22 + v20;
    v24 = ((v10 + k[(v10 >> 11) & 3]) ^ (v23 + ((16 * v23) ^ (v23 >> 5)))) + v21;
    v25 = (v10 + k[v10 & 3]) ^ (v24 + ((16 * v24) ^ (v24 >> 5)));
    v10 -= 1640531527;
    v26 = v25 + v23;
    v27 = ((v10 + k[(v10 >> 11) & 3]) ^ (v26 + ((16 * v26) ^ (v26 >> 5)))) + v24;
    v28 = v10 + k[v10 & 3];
    v10 -= 1640531527;
    v29 = (v28 ^ (v27 + ((16 * v27) ^ (v27 >> 5)))) + v26;
    v30 = ((v10 + k[(v10 >> 11) & 3]) ^ (v29 + ((16 * v29) ^ (v29 >> 5)))) + v27;
    v31 = (v10 + k[v10 & 3]) ^ (v30 + ((16 * v30) ^ (v30 >> 5)));
    v10 -= 1640531527;
    v32 = v31 + v29;
    v33 = ((v10 + k[(v10 >> 11) & 3]) ^ (v32 + ((16 * v32) ^ (v32 >> 5)))) + v30;
    v34 = (v10 + k[v10 & 3]) ^ (v33 + ((16 * v33) ^ (v33 >> 5)));
    v10 -= 1640531527;
    v35 = v34 + v32;
    v36 = ((v10 + k[(v10 >> 11) & 3]) ^ (v35 + ((16 * v35) ^ (v35 >> 5)))) + v33;
    v37 = (v10 + k[v10 & 3]) ^ (v36 + ((16 * v36) ^ (v36 >> 5)));
    v10 -= 1640531527;
    v38 = v37 + v35;
    v39 = ((v10 + k[(v10 >> 11) & 3]) ^ (v38 + ((16 * v38) ^ (v38 >> 5)))) + v36;
    v40 = (v10 + k[v10 & 3]) ^ (v39 + ((16 * v39) ^ (v39 >> 5)));
    v10 -= 1640531527;
    v41 = v40 + v38;
    v42 = ((v10 + k[(v10 >> 11) & 3]) ^ (v41 + ((16 * v41) ^ (v41 >> 5)))) + v39;
    v43 = (v10 + k[v10 & 3]) ^ (v42 + ((16 * v42) ^ (v42 >> 5)));
    v10 -= 1640531527;
    v44 = v43 + v41;
    v45 = ((v10 + k[(v10 >> 11) & 3]) ^ (v44 + ((16 * v44) ^ (v44 >> 5)))) + v42;
    v46 = ((v10 + k[v10 & 3]) ^ (v45 + ((16 * v45) ^ (v45 >> 5)))) + v44;
    v10 -= 1640531527;
    v47 = ((v10 + k[(v10 >> 11) & 3]) ^ (v46 + ((16 * v46) ^ (v46 >> 5)))) + v45;
    v48 = (v10 + k[v10 & 3]) ^ (v47 + ((16 * v47) ^ (v47 >> 5)));
    v10 -= 1640531527;
    v49 = v48 + v46;
    v50 = ((v10 + k[(v10 >> 11) & 3]) ^ (v49 + ((16 * v49) ^ (v49 >> 5)))) + v47;
    v51 = (v10 + k[v10 & 3]) ^ (v50 + ((16 * v50) ^ (v50 >> 5)));
    v10 -= 1640531527;
    v52 = v51 + v49;
    v53 = ((v10 + k[(v10 >> 11) & 3]) ^ (v52 + ((16 * v52) ^ (v52 >> 5)))) + v50;
    v54 = (v10 + k[v10 & 3]) ^ (v53 + ((16 * v53) ^ (v53 >> 5)));
    v3 = v10 - 1640531527;
    v2 = v54 + v52;
    v7 = v3;
    v4 = ((v3 + k[(v3 >> 11) & 3]) ^ (v2 + ((16 * v2) ^ (v2 >> 5)))) + v53;
  }
  *v = v2;
  v[1] = v4;
}
