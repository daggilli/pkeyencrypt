#pragma once

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <format>
#include <functional>
#include <memory>
#include <print>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "commandline.hpp"
#include "fileoperations.hpp"
constexpr int AES_KEY_BYTES = 32;
constexpr int GCM_NONCE_BYTES = 12;
constexpr int GCM_TAG_BYTES = 16;
constexpr int AES_WRAPPED_KEY_BYTES = 512;
constexpr uint8_t MAGIC[4] = {0xB4, 0xFA, 0x52, 0x3F};
constexpr std::size_t MAGIC_LEN = 4;
constexpr uint8_t FORMAT_VERSION[2] = {0x01, 0x00};
constexpr std::size_t FORMAT_VERSION_LEN = 2;
constexpr std::size_t FORMAT_VERSION_OFFSET = MAGIC_LEN;
constexpr std::size_t HEADER_LEN_LEN = 4;
constexpr std::size_t HEADER_LEN_OFFSET = FORMAT_VERSION_OFFSET + FORMAT_VERSION_LEN;
constexpr std::size_t NONCE_LEN = GCM_NONCE_BYTES;
constexpr std::size_t NONCE_LEN_LEN = 2;
constexpr uint8_t NONCE_LEN_VEC[NONCE_LEN_LEN] = {(NONCE_LEN >> 8) & 0xFF, NONCE_LEN & 0xFF};
constexpr std::size_t NONCE_LEN_OFFSET = HEADER_LEN_OFFSET + HEADER_LEN_LEN;
constexpr std::size_t NONCE_OFFSET = NONCE_LEN_OFFSET + NONCE_LEN_LEN;
constexpr std::size_t GCM_TAG_OFFSET = NONCE_OFFSET + GCM_NONCE_BYTES;
constexpr std::size_t AES_WRAPPED_KEY_OFFSET = GCM_TAG_OFFSET + GCM_TAG_BYTES;
constexpr std::size_t HEADER_LEN = AES_WRAPPED_KEY_BYTES + AES_WRAPPED_KEY_OFFSET;
constexpr uint8_t HEADER_LEN_VEC[HEADER_LEN_LEN] = {(HEADER_LEN >> 24) & 0xFF, (HEADER_LEN >> 16) & 0xFF,
                                                    (HEADER_LEN >> 8) & 0xFF, HEADER_LEN & 0xFF};
constexpr std::size_t BLOCK_SIZE = 1024 * 1024;

namespace PKeyEncrypt {
  namespace fs = std::filesystem;

  struct SecureBuffer {
    explicit SecureBuffer(std::size_t size) : buffer(size) {}
    ~SecureBuffer() {
      if (!buffer.empty()) OPENSSL_cleanse(buffer.data(), buffer.size());
    }

    std::vector<uint8_t> buffer;

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
  };

  struct PublicKey {
    PublicKey(FILE* fp) : key_(PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr)) {
      if (key_ == nullptr) {
        throw std::runtime_error("PEM_read_PUBKEY failed");
      }
    }
    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;
    ~PublicKey() {
      if (key_) EVP_PKEY_free(key_);
    }

    EVP_PKEY* key() const noexcept { return key_; }

   private:
    EVP_PKEY* key_;
  };

  struct PrivateKey {
    PrivateKey(FILE* fp) : key_(PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr)) {
      if (!key_) {
        throw std::runtime_error("PEM_read_PUBKEY failed");
      }
    }
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
    ~PrivateKey() {
      if (key_) {
        EVP_PKEY_free(key_);
      }
    }
    EVP_PKEY* key() const noexcept { return key_; }

   private:
    EVP_PKEY* key_;
  };

  struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
      if (ctx) {
        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);
      }
    }
  };

  struct OutputStream {
    OutputStream(const std::string& filename)
        : truePath_{FileOperations::canonicalise(filename)},
          tempPath_{tempname(truePath_)},
          outputStream_{tempPath_, std::ios_base::binary} {
      auto tmp = tempname(FileOperations::canonicalise(filename));
    }
    ~OutputStream() {
      if (!committed_) {
        outputStream_.close();
        fs::remove(tempPath_);
      }
    }
    std::ofstream& stream() noexcept { return outputStream_; }
    const std::ofstream& stream() const noexcept { return outputStream_; }

    std::ostream& write(const char* s, std::streamsize count) { return outputStream_.write(s, count); }

    void commit() {
      outputStream_.flush();
      if (!outputStream_) throw std::runtime_error("Flusing output failed");
      outputStream_.close();
      if (!outputStream_) throw std::runtime_error("Closing output failed");
      fs::rename(tempPath_, truePath_);
      committed_ = true;
    }

   private:
    fs::path truePath_;
    fs::path tempPath_;
    std::ofstream outputStream_;
    bool committed_ = false;

    fs::path tempname(const fs::path& path) {
      auto temppath{path};
      auto filename = path.filename();
      auto stem = filename.stem().string();
      auto ext = filename.extension().string();
      std::vector<uint8_t> rnd(sizeof(uint32_t));
      if ((RAND_bytes(rnd.data(), sizeof(uint32_t))) != 1) {
        throw std::runtime_error("Generate temp name failed");
      }

      std::ostringstream rndstr;
      for (auto r : rnd) {
        rndstr << std::format("{:02X}", r);
      }
      temppath.replace_filename(std::format("{}_{}{}", stem, rndstr.str(), ext));

      return temppath;
    }
  };

  using FilePtr = std::unique_ptr<FILE, decltype(&std::fclose)>;
  using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

  void seal(const CommandLine::CommandLineOptions& options);

  void open(const CommandLine::CommandLineOptions& options);
}  // namespace PKeyEncrypt