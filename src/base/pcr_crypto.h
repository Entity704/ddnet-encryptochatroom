// ! Full AI generated ! //

#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

class CryptoUtils {
public:
    static bool GenerateX25519KeyPair(std::vector<uint8_t>& out_priv_key, std::vector<uint8_t>& out_pub_key) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* pkey = nullptr;
        bool success = false;

        if (pctx && EVP_PKEY_keygen_init(pctx) > 0 && EVP_PKEY_keygen(pctx, &pkey) > 0) {
            size_t priv_len = 32, pub_len = 32;
            out_priv_key.resize(priv_len);
            out_pub_key.resize(pub_len);

            if (EVP_PKEY_get_raw_private_key(pkey, out_priv_key.data(), &priv_len) > 0 &&
                EVP_PKEY_get_raw_public_key(pkey, out_pub_key.data(), &pub_len) > 0) {
                success = true;
            }
        }
        if (pkey) EVP_PKEY_free(pkey);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        return success;
    }

    static bool X25519_Encrypt(const std::vector<uint8_t>& receiver_pub_bytes,
                               const std::vector<uint8_t>& plaintext,
                               std::vector<uint8_t>& out_packet) {
        EVP_PKEY* receiver_pub = nullptr;
        EVP_PKEY_CTX* pctx = nullptr;
        EVP_PKEY* ephemeral_key = nullptr;
        EVP_CIPHER_CTX* cipher_ctx = nullptr;
        size_t secret_len = 0;
        size_t pub_len = 32;
        int len = 0, final_len = 0;
        bool success = false;

        std::vector<uint8_t> shared_secret;
        std::vector<uint8_t> ephemeral_pub(32);
        std::vector<uint8_t> iv(12);
        std::vector<uint8_t> tag(16);
        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t aes_key[32];

        receiver_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, receiver_pub_bytes.data(), receiver_pub_bytes.size());
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);

        if (!receiver_pub || !pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &ephemeral_key) <= 0) goto cleanup;
        EVP_PKEY_CTX_free(pctx);
        pctx = nullptr;

        pctx = EVP_PKEY_CTX_new(ephemeral_key, nullptr);
        if (!pctx || EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_derive_set_peer(pctx, receiver_pub) <= 0 || EVP_PKEY_derive(pctx, nullptr, &secret_len) <= 0) goto cleanup;
        shared_secret.resize(secret_len);
        if (EVP_PKEY_derive(pctx, shared_secret.data(), &secret_len) <= 0) goto cleanup;

        SHA256(shared_secret.data(), shared_secret.size(), aes_key);

        EVP_PKEY_get_raw_public_key(ephemeral_key, ephemeral_pub.data(), &pub_len);

        RAND_bytes(iv.data(), iv.size());
        cipher_ctx = EVP_CIPHER_CTX_new();
        if (!cipher_ctx ||
            EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), nullptr, aes_key, iv.data()) <= 0 ||
            EVP_EncryptUpdate(cipher_ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) <= 0 ||
            EVP_EncryptFinal_ex(cipher_ctx, ciphertext.data() + len, &final_len) <= 0 ||
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) <= 0) goto cleanup;

        out_packet.clear();
        out_packet.insert(out_packet.end(), ephemeral_pub.begin(), ephemeral_pub.end());
        out_packet.insert(out_packet.end(), iv.begin(), iv.end());
        out_packet.insert(out_packet.end(), tag.begin(), tag.end());
        out_packet.insert(out_packet.end(), ciphertext.begin(), ciphertext.end());
        success = true;

    cleanup:
        if (receiver_pub) EVP_PKEY_free(receiver_pub);
        if (ephemeral_key) EVP_PKEY_free(ephemeral_key);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
        return success;
    }

    static bool X25519_Decrypt(const std::vector<uint8_t>& my_priv_bytes,
                               const std::vector<uint8_t>& packet,
                               std::vector<uint8_t>& out_plaintext) {
        if (packet.size() < (32 + 12 + 16)) return false;

        EVP_PKEY* my_priv = nullptr;
        EVP_PKEY* ephemeral_pub = nullptr;
        EVP_PKEY_CTX* pctx = nullptr;
        EVP_CIPHER_CTX* cipher_ctx = nullptr;
        size_t secret_len = 0;
        int len = 0, final_len = 0;
        bool success = false;

        std::vector<uint8_t> ephemeral_pub_bytes(packet.begin(), packet.begin() + 32);
        std::vector<uint8_t> iv(packet.begin() + 32, packet.begin() + 32 + 12);
        std::vector<uint8_t> tag(packet.begin() + 32 + 12, packet.begin() + 32 + 12 + 16);
        std::vector<uint8_t> ciphertext(packet.begin() + 32 + 12 + 16, packet.end());
        std::vector<uint8_t> shared_secret;
        uint8_t aes_key[32];

        my_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_priv_bytes.data(), my_priv_bytes.size());
        ephemeral_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, ephemeral_pub_bytes.data(), ephemeral_pub_bytes.size());

        if (!my_priv || !ephemeral_pub) goto cleanup;

        pctx = EVP_PKEY_CTX_new(my_priv, nullptr);
        if (!pctx || EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_derive_set_peer(pctx, ephemeral_pub) <= 0 || EVP_PKEY_derive(pctx, nullptr, &secret_len) <= 0) goto cleanup;
        shared_secret.resize(secret_len);
        if (EVP_PKEY_derive(pctx, shared_secret.data(), &secret_len) <= 0) goto cleanup;

        SHA256(shared_secret.data(), shared_secret.size(), aes_key);

        cipher_ctx = EVP_CIPHER_CTX_new();
        out_plaintext.resize(ciphertext.size());
        if (!cipher_ctx ||
            EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), nullptr, aes_key, iv.data()) <= 0 ||
            EVP_DecryptUpdate(cipher_ctx, out_plaintext.data(), &len, ciphertext.data(), ciphertext.size()) <= 0 ||
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) <= 0 ||
            EVP_DecryptFinal_ex(cipher_ctx, out_plaintext.data() + len, &final_len) <= 0) goto cleanup;

        out_plaintext.resize(len + final_len);
        success = true;

    cleanup:
        if (my_priv) EVP_PKEY_free(my_priv);
        if (ephemeral_pub) EVP_PKEY_free(ephemeral_pub);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
        return success;
    }

    static bool GenerateAESKey(std::vector<uint8_t>& out_aes_key) {
        out_aes_key.resize(32);
        return RAND_bytes(out_aes_key.data(), out_aes_key.size()) == 1;
    }

    static bool AES_Encrypt(const std::vector<uint8_t>& aes_key,
                            const std::vector<uint8_t>& plaintext,
                            std::vector<uint8_t>& out_packet) {
        std::vector<uint8_t> iv(12), tag(16), ciphertext(plaintext.size());
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len, final_len;
        bool success = false;

        if (ctx && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aes_key.data(), iv.data()) > 0 &&
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) > 0 &&
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) > 0 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()) > 0) {

            out_packet.clear();
            out_packet.insert(out_packet.end(), iv.begin(), iv.end());
            out_packet.insert(out_packet.end(), tag.begin(), tag.end());
            out_packet.insert(out_packet.end(), ciphertext.begin(), ciphertext.end());
            success = true;
        }
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return success;
    }

    static bool AES_Decrypt(const std::vector<uint8_t>& aes_key,
                            const std::vector<uint8_t>& packet,
                            std::vector<uint8_t>& out_plaintext) {
        if (packet.size() < (12 + 16)) return false;

        std::vector<uint8_t> iv(packet.begin(), packet.begin() + 12);
        std::vector<uint8_t> tag(packet.begin() + 12, packet.begin() + 12 + 16);
        std::vector<uint8_t> ciphertext(packet.begin() + 12 + 16, packet.end());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        out_plaintext.resize(ciphertext.size());
        int len, final_len;
        bool success = false;

        if (ctx && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aes_key.data(), iv.data()) > 0 &&
            EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext.data(), ciphertext.size()) > 0 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) > 0 &&
            EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &final_len) > 0) {

            out_plaintext.resize(len + final_len);
            success = true;
        }
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return success;
    }
};

class Base32768 {
private:
    static uint32_t IndexToCodePoint(uint16_t index) {
        if (index < 27648) return 0x3400 + index;
        else return 0xAC00 + (index - 27648);
    }

    static int32_t CodePointToIndex(uint32_t cp) {
        if (cp >= 0x3400 && cp <= 0x9FFF) return cp - 0x3400;
        else if (cp >= 0xAC00 && cp <= 0xBFFF) return cp - 0xAC00 + 27648;
        return -1;
    }

    static void AppendCodePointAsUTF8(uint32_t cp, std::string& out) {
        if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(0xEF);
            out.push_back(0xBF);
            out.push_back(0xBD);
        }
    }

    static uint32_t NextUTF8CodePoint(const std::string& str, size_t& start_idx) {
        if (start_idx >= str.size()) return 0;
        uint8_t c1 = str[start_idx++];
        if ((c1 & 0x80) == 0) return c1;

        if ((c1 & 0xE0) == 0xC0) {
            if (start_idx >= str.size()) return 0;
            uint8_t c2 = str[start_idx++];
            return ((c1 & 0x1F) << 6) | (c2 & 0x3F);
        } else if ((c1 & 0xF0) == 0xE0) {
            if (start_idx + 1 >= str.size()) return 0;
            uint8_t c2 = str[start_idx++];
            uint8_t c3 = str[start_idx++];
            return ((c1 & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
        }
        return 0;
    }

public:
    static std::string Encode(const std::vector<uint8_t>& data) {
        std::string result;
        uint32_t buffer = 0;
        int bits_left = 0;

        uint16_t origin_len = static_cast<uint16_t>(data.size());
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(origin_len >> 8));
        payload.push_back(static_cast<uint8_t>(origin_len & 0xFF));
        payload.insert(payload.end(), data.begin(), data.end());

        for (uint8_t byte : payload) {
            buffer = (buffer << 8) | byte;
            bits_left += 8;

            while (bits_left >= 15) {
                bits_left -= 15;
                uint16_t index = (buffer >> bits_left) & 0x7FFF;
                AppendCodePointAsUTF8(IndexToCodePoint(index), result);
            }
        }

        if (bits_left > 0) {
            uint16_t index = (buffer << (15 - bits_left)) & 0x7FFF;
            AppendCodePointAsUTF8(IndexToCodePoint(index), result);
        }

        return result;
    }

    static std::vector<uint8_t> Decode(const std::string& str) {
        std::vector<uint8_t> raw_stream;
        uint32_t buffer = 0;
        int bits_left = 0;
        size_t str_idx = 0;

        while (str_idx < str.size()) {
            uint32_t cp = NextUTF8CodePoint(str, str_idx);
            if (cp == 0) break;

            int32_t index = CodePointToIndex(cp);
            if (index == -1) continue;

            buffer = (buffer << 15) | index;
            bits_left += 15;

            while (bits_left >= 8) {
                bits_left -= 8;
                raw_stream.push_back(static_cast<uint8_t>((buffer >> bits_left) & 0xFF));
            }
        }

        if (raw_stream.size() < 2) return {};

        uint16_t expected_len = (static_cast<uint16_t>(raw_stream[0]) << 8) | raw_stream[1];

        std::vector<uint8_t> result;
        if (raw_stream.size() >= static_cast<size_t>(2 + expected_len)) {
            result.insert(result.end(), raw_stream.begin() + 2, raw_stream.begin() + 2 + expected_len);
        }
        return result;
    }
};
