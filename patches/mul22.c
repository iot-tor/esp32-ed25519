// multiplication with blocks of size 22 bits


void unpack22(unsigned int *to,const unsigned char *t_)
{
  const unsigned int *t=(const unsigned int*)t_;
  unsigned int c;
  c=(t[0]);
  to[0]=c&0x3fffff;
  c=(t[0]>>22)|(t[1]<<10);
  to[1]=c&0x3fffff;
  c=(t[1]>>12)|(t[2]<<20);
  to[2]=c&0x3fffff;
  c=(t[2]>>2);
  to[3]=c&0x3fffff;
  c=(t[2]>>24)|(t[3]<<8);
  to[4]=c&0x3fffff;
  c=(t[3]>>14)|(t[4]<<18);
  to[5]=c&0x3fffff;
  c=(t[4]>>4);
  to[6]=c&0x3fffff;
  c=(t[4]>>26)|(t[5]<<6);
  to[7]=c&0x3fffff;
  c=(t[5]>>16)|(t[6]<<16);
  to[8]=c&0x3fffff;
  c=(t[6]>>6);
  to[9]=c&0x3fffff;
  c=(t[6]>>28)|(t[7]<<4);
  to[10]=c&0x3fffff;
  c=(t[7]>>18);
  to[11]=c&0x3fff;

}

void pack22(const unsigned int *to,unsigned char *t_)
{
  unsigned int c;
  unsigned int *t=(unsigned int*)t_;

  c=(to[0])|(to[1]<<22);
  t[0]=c;
  c=(to[1]>>10)|(to[2]<<12);
  t[1]=c;
  c=(to[2]>>20)|(to[3]<<2)|(to[4]<<24);
  t[2]=c;
  c=(to[4]>>8)|(to[5]<<14);
  t[3]=c;
  c=(to[5]>>18)|(to[6]<<4)|(to[7]<<26);
  t[4]=c;
  c=(to[7]>>6)|(to[8]<<16);
  t[5]=c;
  c=(to[8]>>16)|(to[9]<<6)|(to[10]<<28);
  t[6]=c;
  c=(to[10]>>4)|(to[11]<<18);
  t[7]=c;
}

void f25519_mul__distinct(f25519_t r, const f25519_t a, const f25519_t b)
{
  unsigned long long c = 0;

  unsigned int aa[12];
  unsigned int bb[12];
  unsigned int rr[12];
  unpack22(aa,a);
  unpack22(bb,b);
  
  for (int i = 0; i < 12; i++) {
    int j;
    
    c >>= 22;
    for (j = 0; j <= i; j++)
      c += ((uint64_t)aa[j]) * (bb[i - j]);

    for (; j < 12; j++)
      c += ((uint64_t)aa[j]) *	(bb[i + 12 - j]) * 9728; // 9728 is (2^(12*22) % (2^255-19)

    rr[i] = c&0x3fffff;
  }
  rr[11] &= 0x1fff;
  c = (c >> 13) * 19;

  for (int i = 0; i < 12; i++) {
    c += rr[i];
    rr[i] = c&0x3fffff;
    c >>= 22;
  }

  pack22(rr,r);

}
