#ifndef SM4_H
#define SM4_H

#include <cstdint>
#include <cstddef>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

enum class SM4Impl {
    BASIC,
    TTABLE,
    SHUFFLE
};

class SM4 {
public:
    virtual ~SM4() = default;

    virtual void set_key(const uint8_t* key) = 0;

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

    static SM4* create(SM4Impl impl);
};

class SM4_Basic : public SM4 {
public:
    SM4_Basic();
    ~SM4_Basic() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[32];
};

class SM4_TTable : public SM4 {
public:
    SM4_TTable();
    ~SM4_TTable() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[32];
};

class SM4_Shuffle : public SM4 {
public:
    SM4_Shuffle();
    ~SM4_Shuffle() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

    void encrypt_4blocks(const uint8_t* in, uint8_t* out) const;

private:
    uint32_t rk_[32];
};

#endif // SM4_H
