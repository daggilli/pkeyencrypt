#pragma once

#include <getopt.h>

#include <filesystem>
#include <format>
#include <iostream>
#include <optional>
#include <print>
#include <stdexcept>

namespace PKeyEncrypt::CommandLine {
  namespace fs = std::filesystem;

  class CommandLineOptions {
   public:
    explicit CommandLineOptions() : mode_(std::nullopt), forceoverwrite_(false) {}
    explicit CommandLineOptions(int argc, char* const argv[]) : mode_(std::nullopt), forceoverwrite_(false) {
      parse(argc, argv);
    }

    void parse(int argc, char* const argv[]) {
      // fs::path inputfile;
      // fs::path outputfile;
      // fs::path keyfile;

      const option long_options[] = {{"enc", no_argument, nullptr, 'e'},
                                     {"dec", no_argument, nullptr, 'd'},
                                     {"infile", required_argument, nullptr, 'i'},
                                     {"outfile", required_argument, nullptr, 'o'},
                                     {"key", required_argument, nullptr, 'k'},
                                     {"overwrite", no_argument, nullptr, 'w'},
                                     // {"help",    no_argument,       nullptr, 'h'},
                                     {nullptr, 0, nullptr, 0}};

      int opt;

      while ((opt = getopt_long(argc, argv, "edi:o:k:hw", long_options, nullptr)) != -1) {
        if (opt == '?') break;
        switch (opt) {
          case 'e': {
            if (mode_.has_value()) {
              throw std::invalid_argument("Encryption/decryption mode specified twice");
            }
            mode_ = true;
            break;
          }

          case 'd': {
            if (mode_.has_value()) {
              throw std::invalid_argument("Encryption/decryption mode specified twice");
            }
            mode_ = false;
            break;
          }

          case 'i': {
            inputfile_ = optarg;
            break;
          }

          case 'o': {
            outputfile_ = optarg;
            break;
          }

          case 'k': {
            keyfile_ = optarg;
            break;
          }

          case 'w': {
            forceoverwrite_ = true;
            break;
          }

            // case 'h':
            //   usage(argv[0]);
            //   return 0;

          default: {
            throw std::invalid_argument("Unrecognised argument");
          }
        }
      }

      if (!mode_.has_value() || inputfile_.empty() || outputfile_.empty() || keyfile_.empty() ||
          optind != argc) {
        throw std::invalid_argument("Could not parse command line arguments");
      }
    }

    static void usage() { std::println("Usage : TODO"); }

    const auto mode() const { return mode_.value(); }
    const auto& inputfile() const { return inputfile_; }
    const auto& outputfile() const { return outputfile_; }
    const auto& keyfile() const { return keyfile_; }
    const auto forceoverwrite() const { return forceoverwrite_; }

   private:
    std::optional<bool> mode_;
    bool forceoverwrite_;
    std::string inputfile_;
    std::string outputfile_;
    std::string keyfile_;
  };
}  // namespace PKeyEncrypt::CommandLine
