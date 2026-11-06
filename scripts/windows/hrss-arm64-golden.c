#include <openssl/hrss.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int digest_matches(const uint8_t *data, size_t length, const char *hex) {
  static const char digits[] = "0123456789abcdef";
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(data, length, digest);
  for (size_t i = 0; i < sizeof(digest); i++) {
    if (hex[2 * i] != digits[digest[i] >> 4] ||
        hex[2 * i + 1] != digits[digest[i] & 15]) return 0;
  }
  return hex[2 * sizeof(digest)] == 0;
}

int main(void) {
  uint8_t key_entropy[HRSS_GENERATE_KEY_BYTES];
  for (unsigned i = 0; i < HRSS_SAMPLE_BYTES; i++) key_entropy[i] = (uint8_t)i;
  for (unsigned i = HRSS_SAMPLE_BYTES; i < 2 * HRSS_SAMPLE_BYTES; i++)
    key_entropy[i] = (uint8_t)(2 + i);
  for (unsigned i = 2 * HRSS_SAMPLE_BYTES; i < sizeof(key_entropy); i++)
    key_entropy[i] = (uint8_t)(4 + i);
  struct HRSS_public_key pub;
  struct HRSS_private_key priv;
  memset(&pub, 0, sizeof(pub));
  memset(&priv, 0, sizeof(priv));
  if (!HRSS_generate_key(&pub, &priv, key_entropy)) return 10;
  uint8_t public_bytes[HRSS_PUBLIC_KEY_BYTES];
  HRSS_marshal_public_key(public_bytes, &pub);
  if (!digest_matches(public_bytes, sizeof(public_bytes),
      "5ed9ba05352d983de9b51692658bf41b657ea868931df0ac5bf13f42c90161d7")) return 11;
  uint8_t encap_entropy[HRSS_ENCAP_BYTES];
  for (size_t i = 0; i < sizeof(encap_entropy); i++) encap_entropy[i] = (uint8_t)(31 + i);
  uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
  uint8_t shared[HRSS_KEY_BYTES];
  if (!HRSS_encap(ciphertext, shared, &pub, encap_entropy)) return 20;
  if (!digest_matches(ciphertext, sizeof(ciphertext),
      "9c65360e09ca97e342920b817de203ffbfeb9e66a4b1e1027447bd46a207dc8e")) return 21;
  if (!digest_matches(shared, sizeof(shared),
      "6966cc8ab54a6f8e95d9a8ed21433a758e3f852ff1ed8aa5309a7053e879c71a")) return 22;
  if (!HRSS_decap(shared, &priv, ciphertext, sizeof(ciphertext))) return 30;
  if (!digest_matches(shared, sizeof(shared),
      "6966cc8ab54a6f8e95d9a8ed21433a758e3f852ff1ed8aa5309a7053e879c71a")) return 31;
  ciphertext[50] ^= 4;
  if (!HRSS_decap(shared, &priv, ciphertext, sizeof(ciphertext))) return 40;
  if (!digest_matches(shared, sizeof(shared),
      "9c1f7220927f4dc7de007da6ac352216595a686f9718f0f3d70f0526257a2fdb")) return 41;
  puts("HRSS upstream Golden PASS");
  return 0;
}
