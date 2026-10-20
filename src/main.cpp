#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <cerrno>
#include <cstdlib>
#include <optional>
#include <print>

#include "commandline.hpp"
#include "fileoperations.hpp"
#include "pkeyencrypt.hpp"

using namespace PKeyEncrypt;

int main(int argc, char *argv[]) {
  CommandLine::CommandLineOptions options;

  try {
    options.parse(argc, argv);
  } catch (std::invalid_argument &e) {
    std::println("Error: {}", e.what());
    CommandLine::CommandLineOptions::usage();
    exit(-EINVAL);
  }

  auto errMessage = FileOperations::diagnoseError(FileOperations::validateFiles(options));

  if (errMessage.has_value()) {
    std::println("Error: {}", errMessage.value());
    exit(-EINVAL);
  }

  options.mode() ? seal(options) : open(options);

  // if (options.mode()) {
  //   seal(options);
  // } else {
  //   open(options);
  // }

  return EXIT_SUCCESS;
}
