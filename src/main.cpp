#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/sm2.h>
#include <openssl/err.h>

void print_error(const char* msg) {
    char error_msg[120];
    ERR_error_string(ERR_get_error(), error_msg);
    std::cerr << msg << ": " << error_msg << std::endl;
}

void generate_keypair(EC_KEY** key_pair) {
    // 创建椭圆曲线SM2的密钥对对象
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_sm2);
    if (key == nullptr) {
        print_error("Failed to create EC_KEY");
        return;
    }
    
    // 生成SM2密钥对
    if (EC_KEY_generate_key(key) != 1) {
        print_error("Failed to generate SM2 key pair");
        EC_KEY_free(key);
        return;
    }
    
    *key_pair = key;
}

void sm2_encrypt(const EC_KEY* key, const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext, size_t* ciphertext_len) {
    // 创建EVP_PKEY对象，用于存储SM2密钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr) {
        print_error("Failed to create EVP_PKEY");
        return;
    }
    
    // 将SM2密钥对设置到EVP_PKEY对象中
    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1) {
        print_error("Failed to set EVP_PKEY");
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 创建EVP_PKEY_CTX对象，用于加密操作的上下文管理
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (ctx == nullptr) {
        print_error("Failed to create EVP_PKEY_CTX");
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 初始化加密上下文
    if (EVP_PKEY_encrypt_init(ctx) != 1) {
        print_error("Failed to initialize encryption context");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 进行SM2加密
    if (EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) != 1) {
        print_error("Failed to encrypt data");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

void sm2_decrypt(const EC_KEY* key, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext, size_t* plaintext_len) {
    // 创建EVP_PKEY对象，用于存储SM2密钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr) {
        print_error("Failed to create EVP_PKEY");
        return;
    }
    
    // 将SM2密钥对设置到EVP_PKEY对象中
    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1) {
        print_error("Failed to set EVP_PKEY");
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 创建EVP_PKEY_CTX对象，用于解密操作的上下文管理
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (ctx == nullptr) {
        print_error("Failed to create EVP_PKEY_CTX");
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 初始化解密上下文
    if (EVP_PKEY_decrypt_init(ctx) != 1) {
        print_error("Failed to initialize decryption context");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    // 进行SM2解密
    if (EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len) != 1) {
        print_error("Failed to decrypt data");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

int main() {
    EC_KEY* key_pair = nullptr;
    generate_keypair(&key_pair);
    
    const unsigned char plaintext[] = "Hello, SM2!";
    const size_t plaintext_len = sizeof(plaintext) - 1;
    
    unsigned char ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);
    
    // 使用SM2公钥加密数据
    sm2_encrypt(key_pair, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    
    unsigned char decrypted_plaintext[1024];
    size_t decrypted_plaintext_len = sizeof(decrypted_plaintext);
    
    // 使用SM2私钥解密数据
    sm2_decrypt(key_pair, ciphertext, ciphertext_len, decrypted_plaintext, &decrypted_plaintext_len);
    
    std::cout << "Decrypted plaintext: " << decrypted_plaintext << std::endl;
    
    EC_KEY_free(key_pair);
    
    return 0;
}
