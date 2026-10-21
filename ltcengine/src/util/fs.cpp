#include "ltc/util/fs.hpp"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace ltc {
namespace fs {
namespace {

namespace stdfs = std::filesystem;

}  // namespace

std::string join(const std::string& a, const std::string& b) {
  return (stdfs::path(a) / b).string();
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return stdfs::exists(path, ec) && !ec;
}

void ensure_dir(const std::string& path) {
  std::error_code ec;
  stdfs::create_directories(path, ec);
  if (ec) throw std::runtime_error("failed to create directory: " + path);
  if (!stdfs::is_directory(path)) throw std::runtime_error("path is not a directory: " + path);
}

void ensure_directory(const std::string& path) { ensure_dir(path); }

Bytes read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("failed to open file for reading: " + path);
  in.seekg(0, std::ios::end);
  std::streamoff len = in.tellg();
  if (len < 0) throw std::runtime_error("failed to size file: " + path);
  in.seekg(0, std::ios::beg);
  Bytes out(static_cast<size_t>(len));
  if (len > 0) {
    in.read(reinterpret_cast<char*>(out.data()), len);
    if (!in) throw std::runtime_error("failed to read file: " + path);
  }
  return out;
}

std::string read_text(const std::string& path) {
  Bytes raw = read_file(path);
  return std::string(raw.begin(), raw.end());
}

void write_file(const std::string& path, const Bytes& data) {
  stdfs::path p(path);
  if (p.has_parent_path()) {
    std::error_code ec;
    stdfs::create_directories(p.parent_path(), ec);
    if (ec) throw std::runtime_error("failed to create directory for: " + path);
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) throw std::runtime_error("failed to open file for writing: " + path);
  if (!data.empty()) {
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!out) throw std::runtime_error("failed to write file: " + path);
  }
}

void write_file(const std::string& path, const std::string& text) {
  write_file(path, Bytes(text.begin(), text.end()));
}

void append_file(const std::string& path, const Bytes& data) {
  if (data.empty()) return;
  stdfs::path p(path);
  if (p.has_parent_path()) {
    std::error_code ec;
    stdfs::create_directories(p.parent_path(), ec);
    if (ec) throw std::runtime_error("failed to create directory for: " + path);
  }
  std::ofstream out(path, std::ios::binary | std::ios::app);
  if (!out) throw std::runtime_error("failed to open file for append: " + path);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  if (!out) throw std::runtime_error("failed to append file: " + path);
}

}  // namespace fs
}  // namespace ltc
