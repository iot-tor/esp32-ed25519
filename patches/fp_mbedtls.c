void mpi_initload(mbedtls_mpi *x,const unsigned char *n,int len)
{
  unsigned char r[64];
  for(int u=0;u<len;u++)
    r[u]=n[len-1-u];
  mbedtls_mpi_init(x);
  mbedtls_mpi_read_binary(x,r,len);
}

void mpi_writebin(mbedtls_mpi *x,unsigned char *n,int len)
{
  unsigned char r[64];
  mbedtls_mpi_write_binary(x,r,len);
  for(int u=0;u<len;u++)
    n[u]=r[len-1-u];
}

void fprime_add(uint8_t *r, const uint8_t *a, const uint8_t *modulus)
{
  mbedtls_mpi rn,an,mn;

  mpi_initload(&rn,r,32);
  mpi_initload(&an,a,32);
  mpi_initload(&mn,modulus,32);

  mbedtls_mpi_add_mpi(&rn,&rn,&an);
  mbedtls_mpi_mod_mpi(&rn,&rn,&mn);

  mpi_writebin(&rn,r,32);

  mbedtls_mpi_free(&an);
  mbedtls_mpi_free(&rn);
  mbedtls_mpi_free(&mn);
}

void fprime_mul(uint8_t *r, const uint8_t *a, const uint8_t *b,
		const uint8_t *modulus)
{
  mbedtls_mpi an,bn,mn;

  mpi_initload(&bn,b,32);
  mpi_initload(&an,a,32);
  mpi_initload(&mn,modulus,32);

  mbedtls_mpi_mul_mpi(&an,&an,&bn);
  mbedtls_mpi_mod_mpi(&an,&an,&mn);

  mpi_writebin(&an,r,32);

  mbedtls_mpi_free(&an);
  mbedtls_mpi_free(&bn);
  mbedtls_mpi_free(&mn);
}

void fprime_from_bytes(uint8_t *n,
		       const uint8_t *x, size_t len,
		       const uint8_t *modulus)
{
  mbedtls_mpi bnx,bnm;
  mpi_initload(&bnx,x,len);
  mpi_initload(&bnm,modulus,32);

  mbedtls_mpi_mod_mpi(&bnx,&bnx,&bnm);

  mpi_writebin(&bnx,n,32);
  mbedtls_mpi_free(&bnm);
  mbedtls_mpi_free(&bnx);
}

