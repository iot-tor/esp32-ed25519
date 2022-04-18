static void hash_with_prefix(uint8_t *out_fp,
			     uint8_t *init_block, unsigned int prefix_size,
			     const uint8_t *message, size_t len)
{
  mbedtls_sha512_context ctx;
  mbedtls_sha512_init(&ctx);
  mbedtls_sha512_starts(&ctx,0);
  mbedtls_sha512_update(&ctx, init_block, prefix_size);
  mbedtls_sha512_update(&ctx, message, len);
  mbedtls_sha512_finish(&ctx, init_block);
  mbedtls_sha512_free(&ctx);
  fprime_from_bytes(out_fp, init_block, SHA512_HASH_SIZE, ed25519_order);
}

