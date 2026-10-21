#pragma once
#include <string>

namespace ltc {
namespace tui {

// Interactive wallet TUI. Returns process exit code.
int run(const std::string& default_datadir = "");

}  // namespace tui
}  // namespace ltc
