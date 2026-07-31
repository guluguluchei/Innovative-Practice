#ifndef TWINE_H
#define TWINE_H

#include <cstdint>
#include <cstddef>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

enum class TWINEImpl {
    BASIC,
    TTABLE,
    SHUFFLE
};

class TWINE {
public:
    virtual ~TWINE() = default;

    virtual void set_key(const uint8_t* key, size_t key_len) = 0;

    virtual void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const = 0;

    virtual void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const = 0;

    void encrypt_blocks(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
        for (size_t i = 0; i < num_blocks; i++) {
            encrypt_block(in + 8 * i, out + 8 * i);
        }
    }

    void decrypt_blocks(const uint8_t* in, uint8_t* out, size_t num_blocks) const {
        for (size_t i = 0; i < num_blocks; i++) {
            decrypt_block(in + 8 * i, out + 8 * i);
        }
    }

    static TWINE* create(TWINEImpl impl);
};

class TWINE_Basic : public TWINE {
public:
    TWINE_Basic();
    ~TWINE_Basic() override;

    void set_key(const uint8_t* key, size_t key_len) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[36];
};

class TWINE_TTable : public TWINE {
public:
    TWINE_TTable();
    ~TWINE_TTable() override;

    void set_key(const uint8_t* key, size_t key_len) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[36];
};

class TWINE_Shuffle : public TWINE {
public:
    TWINE_Shuffle();
    ~TWINE_Shuffle() override;

    void set_key(const uint8_t* key, size_t key_len) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

    void encrypt_2blocks(const uint8_t* in, uint8_t* out) const;

private:
    uint32_t rk_[36];
};

#endif
