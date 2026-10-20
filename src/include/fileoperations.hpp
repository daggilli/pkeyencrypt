#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>

#include "commandline.hpp"

using namespace PKeyEncrypt;

namespace PKeyEncrypt::FileOperations {
  namespace fs = std::filesystem;

  inline static fs::path canonicalise(const std::string& pathstr);

  enum FileError {
    noErr,
    inputFileNotFoundErr,
    keyFileNotFoundErr,
    emptyInputFileErr,
    emptyKeyFileErr,
    inputFileUnreadableErr,
    keyFileUnreadableErr,
    fileUnwritableErr,
    outputFileExistsErr,
    duplicateFilenameErr,
  };

  inline FileError validateFiles(const CommandLine::CommandLineOptions& options) {
    auto inputfilepath = canonicalise(options.inputfile());
    if (!fs::exists(inputfilepath)) return inputFileNotFoundErr;

    {
      auto ifs = std::ifstream(inputfilepath);
      if (!ifs.good()) return inputFileUnreadableErr;
    }

    auto fsize = fs::file_size(inputfilepath);
    if (fsize == 0) {
      return emptyInputFileErr;
    }

    auto keyfilepath = canonicalise(options.keyfile());
    if (!fs::exists(keyfilepath)) return keyFileNotFoundErr;

    {
      auto ifs = std::ifstream(keyfilepath);
      if (!ifs.good()) return keyFileUnreadableErr;
    }

    fsize = fs::file_size(keyfilepath);
    if (fsize == 0) {
      return emptyKeyFileErr;
    }

    auto outExists = false;

    fs::path outputfilepath;

    try {
      outputfilepath = canonicalise(options.outputfile());

      if (inputfilepath == outputfilepath) return duplicateFilenameErr;

      if (fs::exists(outputfilepath)) {
        if (fs::equivalent(inputfilepath, outputfilepath)) return duplicateFilenameErr;

        if (!options.forceoverwrite()) return outputFileExistsErr;
        outExists = true;
      }
    } catch (std::exception& e) {
      throw e;
      return fileUnwritableErr;
    }

    {
      try {
        auto ofs = std::ofstream(outputfilepath, std::ios_base::app);
        if (!ofs.good()) return fileUnwritableErr;
        if (!outExists) {
          fs::remove(outputfilepath);
        }
      } catch (std::exception& e) {
        return fileUnwritableErr;
      }
    }

    return noErr;
  }

  constexpr std::optional<std::string> diagnoseError(const FileError err) {
    std::optional<std::string> message;

    switch (err) {
      case noErr: {
        break;
      }

      case inputFileNotFoundErr: {
        message = "Input file not found";
        break;
      }

      case keyFileNotFoundErr: {
        message = "Key file not found";
        break;
      }

      case emptyInputFileErr: {
        message = "Input file empty";
        break;
      }

      case emptyKeyFileErr: {
        message = "Key file empty";
        break;
      }

      case inputFileUnreadableErr: {
        message = "Input file unreadable";
        break;
      }

      case keyFileUnreadableErr: {
        message = "Key file unreadable";
        break;
      }

      case fileUnwritableErr: {
        message = "Output file unwritable";
        break;
      }

      case outputFileExistsErr: {
        message = "Ouput file already exists";
        break;
      }

      case duplicateFilenameErr: {
        message = "Input and output filenames refer to same location";
        break;
      }

      default: {
        throw std::runtime_error("Uknown filesystem error code");
      }
    }
    return message;
  }

  inline fs::path canonicalise(const std::string& pathstr) {
    return fs::weakly_canonical(fs::absolute(pathstr));
  }
}  // namespace PKeyEncrypt::FileOperations