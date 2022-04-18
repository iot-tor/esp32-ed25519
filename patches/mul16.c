void f25519_mul__distinct(f25519_t r, const f25519_t a, const f25519_t b) //modified multiplication 
{
  unsigned short *aa=(unsigned short*)a;
  unsigned short *bb=(unsigned short*)b;
  unsigned short *rr=(unsigned short*)r;
  unsigned long long c = 0;
  int i;
	
  for (i = 0; i < 16; i++) {
    int j;
    
    c >>= 16;
    for (j = 0; j <= i; j++)
      c += ((uint64_t)aa[j]) * ((uint32_t)bb[i - j]);
    
    for (; j < 16; j++)
      c += ((uint64_t)aa[j]) *
	((uint32_t)bb[i + 16 - j]) * 38;
    
    rr[i] = c;
  }
  
  rr[15] &= 0x7fff;
  c = (c >> 15) * 19;

  for (i = 0; i < 16; i++) {
    c += rr[i];
    rr[i] = c;
    c >>= 16;
  }
}
