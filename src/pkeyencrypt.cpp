#include "pkeyencrypt.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <print>
#include <sstream>
#include <stdexcept>

namespace PKeyEncrypt {
  namespace fs = std::filesystem;

  void seal(const CommandLine::CommandLineOptions& options) {
#ifdef LOGGING
    auto logfile = std::ofstream("encrypt.log");
#endif
    FilePtr keyFile(std::fopen(options.keyfile().c_str(), "rb"), &std::fclose);

    auto publicKey = PublicKey(keyFile.get());

    auto aesBuffer = SecureBuffer(AES_KEY_BYTES);
    auto nonceBuffer = SecureBuffer(GCM_NONCE_BYTES);

    if ((RAND_bytes(aesBuffer.buffer.data(), AES_KEY_BYTES)) != 1) {
      throw std::runtime_error("Generate AES key failed");
    }

#ifdef LOGGING
    auto i = 0u;

    logfile << "AES KEY:\n";
    for (auto e : aesBuffer.buffer) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    if ((RAND_bytes(nonceBuffer.buffer.data(), GCM_NONCE_BYTES)) != 1) {
      throw std::runtime_error("Generate GCM nonce failed");
    }

#ifdef LOGGING
    logfile << "NONCE: ";
    for (auto e : nonceBuffer.buffer) {
      logfile << std::format("{:02X} ", e);
    }

    logfile << '\n';
#endif

    PKeyCtx pkCtx(EVP_PKEY_CTX_new(publicKey.key(), nullptr), &EVP_PKEY_CTX_free);

    if (!pkCtx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_encrypt_init(pkCtx.get()) <= 0) throw std::runtime_error("EVP_PKEY_encrypt_init failed");

    if (EVP_PKEY_CTX_set_rsa_padding(pkCtx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
      throw std::runtime_error("Setting RSA-OAEP padding failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkCtx.get(), EVP_sha256()) <= 0)
      throw std::runtime_error("Setting OAEP SHA-256 failed");

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkCtx.get(), EVP_sha256()) <= 0)
      throw std::runtime_error("Setting MGF1 SHA-256 failed");

    size_t wrappedLength = 0;

    if (EVP_PKEY_encrypt(pkCtx.get(), nullptr, &wrappedLength, aesBuffer.buffer.data(),
                         aesBuffer.buffer.size()) <= 0)
      throw std::runtime_error("RSA output size query failed");

    std::vector<unsigned char> wrappedKey(wrappedLength);

    if (EVP_PKEY_encrypt(pkCtx.get(), wrappedKey.data(), &wrappedLength, aesBuffer.buffer.data(),
                         aesBuffer.buffer.size()) <= 0)
      throw std::runtime_error("RSA key wrapping failed");

    wrappedKey.resize(wrappedLength);

#ifdef LOGGING
    i = 0u;

    logfile << "WRAPPED KEY:\n";
    for (auto e : wrappedKey) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    CipherCtx ciphCtx(EVP_CIPHER_CTX_new());

    if (!ciphCtx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ciphCtx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
      throw std::runtime_error("GCM initialisation failed");

    if (EVP_CIPHER_CTX_ctrl(ciphCtx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceBuffer.buffer.size(), nullptr) != 1)
      throw std::runtime_error("Set GCM nonce length failed");

    if (EVP_EncryptInit_ex(ciphCtx.get(), nullptr, nullptr, aesBuffer.buffer.data(),
                           nonceBuffer.buffer.data()) != 1)
      throw std::runtime_error("AES key/nonce initialisation failed");

    std::vector<uint8_t> header(HEADER_LEN);
    std::memcpy(header.data(), MAGIC, MAGIC_LEN);
    std::memcpy(header.data() + FORMAT_VERSION_OFFSET, FORMAT_VERSION, FORMAT_VERSION_LEN);
    std::memcpy(header.data() + HEADER_LEN_OFFSET, HEADER_LEN_VEC, HEADER_LEN_LEN);
    std::memcpy(header.data() + NONCE_LEN_OFFSET, NONCE_LEN_VEC, NONCE_LEN_LEN);
    std::memcpy(header.data() + NONCE_OFFSET, nonceBuffer.buffer.data(), NONCE_LEN);
    std::fill(header.begin() + GCM_TAG_OFFSET, header.begin() + GCM_TAG_OFFSET + GCM_TAG_BYTES, 0);
    std::memcpy(header.data() + AES_WRAPPED_KEY_OFFSET, wrappedKey.data(), AES_WRAPPED_KEY_BYTES);

#ifdef LOGGING
    i = 0u;
    logfile << "HEADER:\n";
    for (auto e : header) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    int len = 0;

    if (EVP_EncryptUpdate(ciphCtx.get(), nullptr, &len, header.data(), header.size()) != 1)
      throw std::runtime_error("Add header AAD failed");

    std::vector<unsigned char> plaintext(BLOCK_SIZE);
    std::vector<unsigned char> ciphertext(BLOCK_SIZE);

    std::ifstream inputFile(options.inputfile(), std::ios_base::binary);
    OutputStream outputFile(options.outputfile());
    outputFile.write(reinterpret_cast<const char*>(header.data()), HEADER_LEN);

    while (inputFile) {
      inputFile.read(reinterpret_cast<char*>(plaintext.data()), plaintext.size());

      const auto bytesRead = inputFile.gcount();

      if (bytesRead == 0) break;

      int bytesWritten = 0;

      if (EVP_EncryptUpdate(ciphCtx.get(), ciphertext.data(), &bytesWritten, plaintext.data(),
                            static_cast<int>(bytesRead)) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

      outputFile.write(reinterpret_cast<const char*>(ciphertext.data()), bytesWritten);
    }

    if (inputFile.bad() || (inputFile.fail() && !inputFile.eof()))
      throw std::runtime_error("Input file read failed");

    if (!outputFile.stream()) throw std::runtime_error("Output file write failed");

    int finalLen = 0;

    if (EVP_EncryptFinal_ex(ciphCtx.get(), ciphertext.data(), &finalLen) != 1)
      throw std::runtime_error("GCM finalisation failed");

    // For GCM, finalLen should be zero.

    std::array<unsigned char, GCM_TAG_BYTES> gcmTag{};

    if (EVP_CIPHER_CTX_ctrl(ciphCtx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, gcmTag.data()) != 1)
      throw std::runtime_error("GCM tag retrieval failed");

#ifdef LOGGING
    logfile << "GDM TAG: ";
    for (auto e : gcmTag) {
      logfile << std::format("{:02X} ", e);
    }

    logfile << '\n';
#endif

    // Patch the tag into the header.
    outputFile.stream().seekp(GCM_TAG_OFFSET, std::ios::beg);

    if (outputFile.stream().bad()) throw std::runtime_error("Seeking to GCM tag failed");

    outputFile.write(reinterpret_cast<const char*>(gcmTag.data()), gcmTag.size());

    if (!outputFile.stream()) {
      throw std::runtime_error("Writing GCM tag failed");
    }

    outputFile.commit();
  }

  void open(const CommandLine::CommandLineOptions& options) {
#ifdef LOGGING
    auto logfile = std::ofstream("decrypt.log");
#endif

    FilePtr keyFile(std::fopen(options.keyfile().c_str(), "rb"), &std::fclose);

    auto privateKey = PrivateKey(keyFile.get());

    std::vector<unsigned char> headerStart(NONCE_OFFSET);
    std::ifstream inputFile(options.inputfile(), std::ios_base::binary);

    inputFile.read(reinterpret_cast<char*>(headerStart.data()), headerStart.size());

#ifdef LOGGING
    logfile << "HDR START: ";
    for (auto e : headerStart) {
      logfile << std::format("{:02X} ", e);
    }

    logfile << '\n';
#endif

    if (!std::equal(headerStart.begin(), headerStart.begin() + MAGIC_LEN, MAGIC))
      throw std::runtime_error("Magic number invalid");

    std::size_t headerLen = (headerStart[HEADER_LEN_OFFSET] << 24) |
                            (headerStart[HEADER_LEN_OFFSET + 1] << 16) |
                            (headerStart[HEADER_LEN_OFFSET + 2] << 8) | headerStart[HEADER_LEN_OFFSET + 3];
    std::size_t nonceLen = (headerStart[NONCE_LEN_OFFSET] << 8) | headerStart[NONCE_LEN_OFFSET + 1];

    std::vector<unsigned char> header(headerLen);
    std::memcpy(header.data(), headerStart.data(), NONCE_OFFSET);

    inputFile.read(reinterpret_cast<char*>(header.data() + NONCE_OFFSET), headerLen - NONCE_OFFSET);

#ifdef LOGGING
    auto i = 0u;
    logfile << "HEADER:\n";
    for (auto e : header) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    std::vector<unsigned char> nonceBuffer(nonceLen);
    std::memcpy(nonceBuffer.data(), header.data() + NONCE_OFFSET, nonceLen);

    std::size_t gcmTagOffset = NONCE_OFFSET + nonceLen;
    std::vector<unsigned char> gcmTag(GCM_TAG_BYTES);
    std::memcpy(gcmTag.data(), header.data() + gcmTagOffset, GCM_TAG_BYTES);

#ifdef LOGGING
    logfile << "NONCE: ";
    for (auto e : nonceBuffer) {
      logfile << std::format("{:02X} ", e);
    }

    logfile << '\n';

    logfile << "GCM TAG: ";
    for (auto e : gcmTag) {
      logfile << std::format("{:02X} ", e);
    }

    logfile << '\n';
#endif

    std::vector<unsigned char> wrappedKey(AES_WRAPPED_KEY_BYTES);
    std::memcpy(wrappedKey.data(), header.data() + AES_WRAPPED_KEY_OFFSET, AES_WRAPPED_KEY_BYTES);

#ifdef LOGGING
    i = 0u;

    logfile << "WRAPPED KEY:\n";
    for (auto e : wrappedKey) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    std::fill(header.begin() + gcmTagOffset, header.begin() + gcmTagOffset + GCM_TAG_BYTES, 0);

#ifdef LOGGING
    i = 0u;
    logfile << "AAD HEADER:\n";
    for (auto e : header) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif
    PKeyCtx pkCtx(EVP_PKEY_CTX_new(privateKey.key(), nullptr), &EVP_PKEY_CTX_free);

    if (!pkCtx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_decrypt_init(pkCtx.get()) <= 0)
      throw std::runtime_error("RSA decrypt initialisation failed");

    if (EVP_PKEY_CTX_set_rsa_padding(pkCtx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
      throw std::runtime_error("RSA padding configuration failed");

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkCtx.get(), EVP_sha256()) <= 0)
      throw std::runtime_error("OAEP digest configuration failed");

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkCtx.get(), EVP_sha256()) <= 0)
      throw std::runtime_error("MGF1 digest configuration failed");

    size_t keyLen = 0;

    if (EVP_PKEY_decrypt(pkCtx.get(), nullptr, &keyLen, wrappedKey.data(), wrappedKey.size()) <= 0)
      throw std::runtime_error("RSA decrypt size query failed");

    auto tempAesBuffer = SecureBuffer(keyLen);

    if (EVP_PKEY_decrypt(pkCtx.get(), tempAesBuffer.buffer.data(), &keyLen, wrappedKey.data(),
                         wrappedKey.size()) <= 0)
      throw std::runtime_error("RSA key unwrapping failed");

    if (keyLen != AES_KEY_BYTES) throw std::runtime_error("Invalid AES session key length");

#ifdef LOGGING
    i = 0u;

    logfile << "TEMP AES KEY:\n";
    for (auto e : tempAesBuffer.buffer) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    auto aesBuffer = SecureBuffer(AES_KEY_BYTES);

    std::memcpy(aesBuffer.buffer.data(), tempAesBuffer.buffer.data(), AES_KEY_BYTES);

#ifdef LOGGING
    i = 0u;

    logfile << "AES KEY:\n";
    for (auto e : aesBuffer.buffer) {
      logfile << std::format("{:02X} ", e);
      i++;
      if (i && (i % 16 == 0)) logfile << '\n';
    }

    logfile << '\n';
#endif

    CipherCtx ciphCtx(EVP_CIPHER_CTX_new());

    if (!ciphCtx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ciphCtx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
      throw std::runtime_error("GCM initialisation failed");
    if (EVP_CIPHER_CTX_ctrl(ciphCtx.get(), EVP_CTRL_GCM_SET_IVLEN, nonceLen, NULL) != 1)
      throw std::runtime_error("Set GCM nonce length failed");

    if (EVP_DecryptInit_ex(ciphCtx.get(), nullptr, nullptr, aesBuffer.buffer.data(), nonceBuffer.data()) != 1)
      throw std::runtime_error("AES key/nonce initialisation failed");

    int len = 0;

    if (EVP_DecryptUpdate(ciphCtx.get(), nullptr, &len, header.data(), header.size()) != 1)
      throw std::runtime_error("Add header AAD failed");

    std::vector<unsigned char> plaintext(BLOCK_SIZE);
    std::vector<unsigned char> ciphertext(BLOCK_SIZE);

    // std::ofstream outputFile(options.outputfile(), std::ios_base::binary);
    OutputStream outputFile(options.outputfile());

    while (inputFile) {
      inputFile.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());

      const auto bytesRead = inputFile.gcount();

      if (bytesRead == 0) break;

      int bytesWritten = 0;

      if (!EVP_DecryptUpdate(ciphCtx.get(), plaintext.data(), &bytesWritten, ciphertext.data(),
                             static_cast<int>(bytesRead)))
        throw std::runtime_error("EVP_DecryptUpdate failed");

      outputFile.write(reinterpret_cast<const char*>(plaintext.data()), bytesWritten);
    }

    if (inputFile.bad() || (inputFile.fail() && !inputFile.eof()))
      throw std::runtime_error("Input file read failed");

    if (!outputFile.stream()) throw std::runtime_error("Output file write failed");

    if (EVP_CIPHER_CTX_ctrl(ciphCtx.get(), EVP_CTRL_GCM_SET_TAG, 16, gcmTag.data()) != 1)
      throw std::runtime_error("GCM tag value does not match");

    int finalLen = 0;

    if (EVP_DecryptFinal_ex(ciphCtx.get(), plaintext.data(), &finalLen) != 1) {
      throw std::runtime_error("GCM finalisation failed");
    }

    outputFile.commit();
  }
}  // namespace PKeyEncrypt