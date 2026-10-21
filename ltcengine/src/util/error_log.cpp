#include "ltc/util/error_log.hpp"

#include "ltc/util/fs.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>

namespace ltc {
namespace {

std::mutex g_mu;
std::string g_path = "errors.txt";

std::string timestamp_now() {
  using clock = std::chrono::system_clock;
  auto t = clock::to_time_t(clock::now());
  std::tm tm{};
#ifdef _WIN32
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

}  // namespace

void set_error_log_path(const std::string& path) {
  std::lock_guard<std::mutex> lock(g_mu);
  g_path = path.empty() ? "errors.txt" : path;
}

void set_error_log_dir(const std::string& dir) {
  if (dir.empty()) {
    set_error_log_path("errors.txt");
    return;
  }
  set_error_log_path(fs::join(dir, "errors.txt"));
}

std::string error_log_path() {
  std::lock_guard<std::mutex> lock(g_mu);
  return g_path;
}

void log_error(const std::string& message, const std::string& context) {
  if (message.empty()) return;
  try {
    std::string path;
    {
      std::lock_guard<std::mutex> lock(g_mu);
      path = g_path;
    }
    std::ostringstream line;
    line << '[' << timestamp_now() << ']';
    if (!context.empty()) line << " [" << context << ']';
    line << ' ' << message << '\n';
    const std::string text = line.str();
    // Best-effort append; never throw out of the logger.
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) return;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
  } catch (...) {
  }
}

}  // namespace ltc
