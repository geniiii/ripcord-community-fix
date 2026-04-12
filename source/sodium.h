#define CRYPTO_AEAD_XCHACHA20POLY1305_IETF_DECRYPT(name) i32 name(u8* m, u64* mlen_p, u8* nsec, const u8* c, u64 clen, const u8* ad, u64 adlen, const u8* npub, const u8* k)
typedef CRYPTO_AEAD_XCHACHA20POLY1305_IETF_DECRYPT(CryptoAeadXchacha20poly1305IetfDecryptType);

#define CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ENCRYPT(name) i32 name(u8* c, u64* clen_p, const u8* m, u64 mlen, const u8* ad, u64 adlen, const u8* nsec, const u8* npub, const u8* k)
typedef CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ENCRYPT(CryptoAeadXchacha20poly1305IetfEncryptType);

static CryptoAeadXchacha20poly1305IetfDecryptType* crypto_aead_xchacha20poly1305_ietf_decrypt;
static CryptoAeadXchacha20poly1305IetfEncryptType* crypto_aead_xchacha20poly1305_ietf_encrypt;
