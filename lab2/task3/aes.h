#ifndef AES_H
#define AES_H

#include <cstdint>
#include <cstddef>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

enum class AESImpl {
    TTABLE,
    AESNI
};

class AES {
public:
    virtual ~AES() = default;

    virtual void set_key(const uint8_t* key, size_t key_len) = 0;

    virtual void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const = 0;

    virtual void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const = 0;

    void encrypt_blocks(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
        for (size_t i = 0; i < num_blocks; i++) {
            encrypt_block(in + 16 * i, out + 16 * i);
        }
    }

    void decrypt_blocks(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
        for (size_t i = 0; i < num_blocks; i++) {
            decrypt_block(in + 16 * i, out + 16 * i);
        }
    }

    static AES* create(AESImpl impl);
};

class AES_TTable : public AES {
public:
    AES_TTable();
    ~AES_TTable() override;

    void set_key(const uint8_t* key, size_t key_len) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t* ek_;
    uint32_t* dk_;
    size_t nr_;
};

class AES_NI : public AES {
public:
    AES_NI();
    ~AES_NI() override;

    void set_key(const uint8_t* key, size_t key_len) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

    void encrypt_blocks_ni(const uint8_t* in, uint8_t* out, size_t num_blocks) const;
    void decrypt_blocks_ni(const uint8_t* in, uint8_t* out, size_t num_blocks) const;

private:
    __m128i round_keys_enc_[15];
    __m128i round_keys_dec_[15];
    size_t nr_;
};

#endif
