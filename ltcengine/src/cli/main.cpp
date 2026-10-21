#include "ltc/cli/tui.hpp"
#include "ltc/wallet/wallet.hpp"
#include "ltc/wallet/script.hpp"
#include "ltc/net/spv.hpp"
#include "ltc/net/bloom.hpp"
#include "ltc/params.hpp"
#include "ltc/util/error_log.hpp"
#include "ltc/crypto/random.hpp"

#include <chrono>
#include <iostream>
#include <string>

namespace {

void usage() {
  std::cerr
      << "ltcengine 1.0.0 — Litecoin SPV wallet\n"
      << "Usage:\n"
      << "  ltcengine                          interactive TUI\n"
      << "  ltcengine tui [datadir]            interactive TUI\n"
      << "  ltcengine create <datadir> <password>\n"
      << "  ltcengine import <datadir> <password> <mnemonic...>\n"
      << "  ltcengine address <datadir> <password> [native|legacy|nested|taproot]\n"
      << "  ltcengine balance <datadir> <password>\n"
      << "  ltcengine sync <datadir> <password>\n"
      << "  ltcengine connect <datadir>        time P2P connect\n"
      << "  ltcengine send <datadir> <password> <to> <amount_sats> [fee_sat_vb]\n"
      << "  ltcengine version\n"
      << "  ltcengine help\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) return ltc::tui::run("./wallet");
    std::string cmd = argv[1];
    if (cmd == "tui" || cmd == "ui" || cmd == "menu") {
      std::string dir = argc >= 3 ? argv[2] : "./wallet";
      return ltc::tui::run(dir);
    }
    // CLI commands that take a datadir: point errors.txt at that folder.
    if (argc >= 3 && (cmd == "create" || cmd == "import" || cmd == "address" || cmd == "balance" ||
                      cmd == "sync" || cmd == "send")) {
      ltc::set_error_log_dir(argv[2]);
    }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
      usage();
      return 0;
    }
    if (cmd == "version" || cmd == "-v" || cmd == "--version") {
      std::cout << "ltcengine 1.0.0\n";
      return 0;
    }

    if (cmd == "create" && argc >= 4) {
      auto w = ltc::Wallet::create_new(argv[2], argv[3]);
      std::cout << "mnemonic: " << w.mnemonic() << "\n";
      std::cout << "address:  " << w.get_new_address() << "\n";
      w.save(argv[3]);
      return 0;
    }
    if (cmd == "import" && argc >= 5) {
      std::string mnemonic;
      for (int i = 4; i < argc; ++i) {
        if (i > 4) mnemonic.push_back(' ');
        mnemonic += argv[i];
      }
      auto w = ltc::Wallet::import_mnemonic(argv[2], mnemonic, argv[3]);
      std::cout << "imported; first address: " << w.get_new_address() << "\n";
      w.save(argv[3]);
      return 0;
    }
    if (cmd == "address" && argc >= 4) {
      auto w = ltc::Wallet::load(argv[2], argv[3]);
      auto type = ltc::WalletAddressType::Native;
      if (argc >= 5) type = ltc::wallet_address_type_from_name(argv[4]);
      std::cout << w.get_new_address(type) << "\n";
      w.save(argv[3]);
      return 0;
    }
    if (cmd == "balance" && argc >= 4) {
      auto w = ltc::Wallet::load(argv[2], argv[3]);
      std::cout << w.balance() << "\n";
      return 0;
    }
    if (cmd == "connect" && argc >= 3) {
      ltc::set_error_log_dir(argv[2]);
      ltc::net::SpvNode spv(argv[2]);
      auto t0 = std::chrono::steady_clock::now();
      try {
        if (!spv.connect_peers(1, 2)) throw std::runtime_error("no peers");
      } catch (const std::exception& e) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        std::cerr << "error after " << ms << " ms: " << e.what() << "\n";
        return 1;
      }
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
      std::cout << "connected peers=" << spv.peer_count() << " in " << ms << " ms";
      if (auto* p = spv.active_peer()) {
        std::cout << " bloom=" << (p->peer_supports_bloom() ? "yes" : "no") << " "
                  << p->peer_user_agent();
      }
      std::cout << "\n";
      return 0;
    }
    if (cmd == "sync" && argc >= 4) {
      auto w = ltc::Wallet::load(argv[2], argv[3]);
      ltc::net::SpvNode spv(argv[2]);
      std::cout << "connecting to Litecoin P2P peers...\n" << std::flush;
      try {
        if (!spv.connect_peers()) throw std::runtime_error("no Litecoin P2P peers available");
      } catch (const std::exception& e) {
        ltc::log_error(e.what(), "sync/connect");
        std::cerr << "error: " << e.what() << "\n";
        return 1;
      }
      std::cout << "peer ok; syncing headers (pruned SPV — no full blocks)...\n" << std::flush;
      uint32_t last_print = 0;
      auto on_progress = [&](uint32_t height, const ltc::Hash256& tip) {
        if (height < last_print + 2000 && height != last_print) return;
        last_print = height;
        std::cout << "height " << height << " tip " << ltc::to_hex(tip.data(), tip.size(), true)
                  << "\n"
                  << std::flush;
      };
      w.sync(spv, on_progress);
      std::cout << "balance " << w.balance() << " tip_height " << spv.tip_height() << "\n";
      w.save(argv[3]);
      return 0;
    }
    if (cmd == "send" && argc >= 6) {
      auto w = ltc::Wallet::load(argv[2], argv[3]);
      int64_t amount = std::stoll(argv[5]);
      int64_t fee = argc >= 7 ? std::stoll(argv[6]) : ltc::params::kDefaultFeeRateSatPerVb;
      ltc::net::SpvNode spv(argv[2]);
      if (!spv.has_peer()) spv.connect_peers();
      std::string txid = w.send(spv, argv[4], amount, fee);
      std::cout << txid << "\n";
      w.save(argv[3]);
      return 0;
    }
    if (cmd == "probe" && argc >= 5) {
      // probe <datadir> <address> <from_height> — bloom-rescan without unlocking wallet
      ltc::set_error_log_dir(argv[2]);
      auto decoded = ltc::decode_address(argv[3]);
      ltc::net::SpvNode spv(argv[2]);
      std::cout << "tip " << spv.tip_height() << " probing " << argv[3] << " from " << argv[4]
                << "\n"
                << std::flush;
      ltc::net::BloomFilter bloom(128, 0.0001, ltc::random_u32(), ltc::net::BLOOM_UPDATE_ALL);
      bloom.insert(decoded.script_pubkey);
      if (!decoded.payload.empty()) bloom.insert(decoded.payload);
      spv.set_bloom(bloom);
      if (!spv.connect_peers()) throw std::runtime_error("no peers");
      spv.send_filterload();
      uint32_t from = static_cast<uint32_t>(std::stoul(argv[4]));
      int matched = 0;
      spv.rescan_filtered(
          from,
          [&](const ltc::Transaction& tx, uint32_t height, const ltc::Hash256&) {
            ++matched;
            std::cout << "MATCH height " << height << " txid "
                      << ltc::to_hex(tx.txid().data(), tx.txid().size(), true) << "\n"
                      << std::flush;
          },
          [&](uint32_t height, const ltc::Hash256&) {
            if (height % 64 == 0)
              std::cout << "rescan " << height << "/" << spv.tip_height() << "\n" << std::flush;
          });
      std::cout << "matched " << matched << "\n";
      return matched > 0 ? 0 : 2;
    }
    usage();
    return 1;
  } catch (const std::exception& e) {
    ltc::log_error(e.what(), "main");
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  } catch (...) {
    ltc::log_error("unknown non-std exception", "main");
    std::cerr << "error: unknown exception\n";
    return 1;
  }
}
