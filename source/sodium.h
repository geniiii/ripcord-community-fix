#define CRYPTO_AEAD_XCHACHA20POLY1305_IETF_DECRYPT(name) int name(unsigned char* m, unsigned long long* mlen_p, unsigned char* nsec, const unsigned char* c, unsigned long long clen, const unsigned char* ad, unsigned long long adlen, const unsigned char* npub, const unsigned char* k)
typedef CRYPTO_AEAD_XCHACHA20POLY1305_IETF_DECRYPT(CryptoAeadXchacha20poly1305IetfDecryptType);

#define CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ENCRYPT(name) int name(unsigned char* c, unsigned long long* clen_p, const unsigned char* m, unsigned long long mlen, const unsigned char* ad, unsigned long long adlen, const unsigned char* nsec, const unsigned char* npub, const unsigned char* k)
typedef CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ENCRYPT(CryptoAeadXchacha20poly1305IetfEncryptType);

#define CRYPTO_SECRETBOX_EASY(name) int name(unsigned char* c, const unsigned char* m, unsigned long long mlen, const unsigned char* n, const unsigned char* k)
typedef CRYPTO_SECRETBOX_EASY(CryptoSecretboxEasyType);

#define CRYPTO_SECRETBOX_OPEN_EASY(name) int name(unsigned char* m, const unsigned char* c, unsigned long long clen, const unsigned char* n, const unsigned char* k)
typedef CRYPTO_SECRETBOX_OPEN_EASY(CryptoSecretboxOpenEasyType);

#define RANDOMBYTES_BUF(name) void name(void* buf, size_t size)
typedef RANDOMBYTES_BUF(RandombytesBufType);

static CryptoAeadXchacha20poly1305IetfDecryptType* crypto_aead_xchacha20poly1305_ietf_decrypt;
static CryptoAeadXchacha20poly1305IetfEncryptType* crypto_aead_xchacha20poly1305_ietf_encrypt;
static CryptoSecretboxEasyType*                     crypto_secretbox_easy;
static CryptoSecretboxOpenEasyType*                 crypto_secretbox_open_easy;
static RandombytesBufType*                          randombytes_buf;
