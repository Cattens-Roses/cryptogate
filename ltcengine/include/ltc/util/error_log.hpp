#pragma once
#include <string>

namespace ltc {

// Directs errors.txt into the wallet data directory (default: ./errors.txt).
void set_error_log_dir(const std::string& dir);

// Absolute or relative path to the log file (overrides dir).
void set_error_log_path(const std::string& path);

std::string error_log_path();

// Append a timestamped line to errors.txt. Never throws.
void log_error(const std::string& message, const std::string& context = {});

}  // namespace ltc
