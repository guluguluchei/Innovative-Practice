#ifndef GIFT_H
#define GIFT_H

#include <cstdint>
#include <cstddef>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

enum class GIFTImpl {
    BASIC,
    BITSLICE,
    SHUFFLE
};

class GIFT {
public:
    virtual ~GIFT() = default;

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

    static GIFT* create(GIFTImpl impl);
};

class GIFT_Basic : public GIFT {
public:
    GIFT_Basic();
    ~GIFT_Basic() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[40];
};

class GIFT_Bitslice : public GIFT {
public:
    GIFT_Bitslice();
    ~GIFT_Bitslice() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

private:
    uint32_t rk_[40];
};

class GIFT_Shuffle : public GIFT {
public:
    GIFT_Shuffle();
    ~GIFT_Shuffle() override;

    void set_key(const uint8_t* key) override;
    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) const override;
    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) const override;

    void encrypt_4blocks(const uint8_t* in, uint8_t* out) const;

private:
    uint32_t rk_[40];
};

#endif
