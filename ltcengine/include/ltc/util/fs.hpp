#pragma once
#include "ltc/util/bytes.hpp"
#include <string>

namespace ltc {
namespace fs {

std::string join(const std::string& a, const std::string& b);
bool file_exists(const std::string& path);
void ensure_dir(const std::string& path);
void ensure_directory(const std::string& path);  // alias

Bytes read_file(const std::string& path);
std::string read_text(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
void write_file(const std::string& path, const std::string& text);
void append_file(const std::string& path, const Bytes& data);

}  // namespace fs

// Convenience aliases in ltc::
inline Bytes read_file(const std::string& path) { return fs::read_file(path); }
inline void write_file(const std::string& path, const Bytes& data) { fs::write_file(path, data); }
inline void ensure_directory(const std::string& path) { fs::ensure_directory(path); }

}  // namespace ltc
