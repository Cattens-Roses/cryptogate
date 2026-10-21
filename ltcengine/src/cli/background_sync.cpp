#include "ltc/cli/background_sync.hpp"

#include "ltc/crypto/random.hpp"
#include "ltc/util/bytes.hpp"
#include "ltc/util/error_log.hpp"

#include <algorithm>
#include <chrono>

namespace ltc {

const char* sync_phase_name(SyncStatus::Phase p) {
  switch (p) {
    case SyncStatus::Phase::Stopped:
      return "stopped";
    case SyncStatus::Phase::Connecting:
      return "connecting";
    case SyncStatus::Phase::SyncingHeaders:
      return "syncing headers";
    case SyncStatus::Phase::Watching:
      return "live / watching";
    case SyncStatus::Phase::Paused:
      return "paused";
    case SyncStatus::Phase::Reconnecting:
      return "reconnecting";
    case SyncStatus::Phase::Error:
      return "error";
  }
  return "unknown";
}

std::string sync_conn_label(const SyncStatus& st) {
  if (!st.conn_status.empty()) return st.conn_status;
  switch (st.phase) {
    case SyncStatus::Phase::Connecting:
      return "connecting";
    case SyncStatus::Phase::Reconnecting:
      return "reconnecting";
    case SyncStatus::Phase::Error:
      return "disconnected";
    case SyncStatus::Phase::Stopped:
      return "disconnected";
    case SyncStatus::Phase::Paused:
      return st.connected ? "connected (paused)" : "paused";
    case SyncStatus::Phase::SyncingHeaders:
    case SyncStatus::Phase::Watching:
      return st.connected ? "connected" : "connecting";
  }
  return "unknown";
}

std::string format_eta(int64_t seconds) {
  if (seconds < 0) return "eta …";
  if (seconds < 60) return "eta " + std::to_string(seconds) + "s";
  if (seconds < 3600) {
    int64_t m = seconds / 60;
    int64_t s = seconds % 60;
    if (s == 0) return "eta " + std::to_string(m) + "m";
    return "eta " + std::to_string(m) + "m " + std::to_string(s) + "s";
  }
  int64_t h = seconds / 3600;
  int64_t m = (seconds % 3600) / 60;
  if (m == 0) return "eta " + std::to_string(h) + "h";
  return "eta " + std::to_string(h) + "h " + std::to_string(m) + "m";
}

std::string sync_progress_label(const SyncStatus& st) {
  uint32_t target = st.target_height;
  if (target == 0 && st.peer_height > 0) target = static_cast<uint32_t>(st.peer_height);
  if (st.rescanning) {
    return "rescanning blocks " + std::to_string(st.rescan_height) + "/" +
           std::to_string(st.tip_height ? st.tip_height : target) +
           (st.eta_seconds >= 0 ? " · " + format_eta(st.eta_seconds) : "");
  }
  if (st.phase == SyncStatus::Phase::SyncingHeaders ||
      (st.phase == SyncStatus::Phase::Watching && target > st.tip_height + 10)) {
    if (target == 0) target = st.tip_height;
    std::string s = "downloading blocks " + std::to_string(st.tip_height) + "/" +
                    std::to_string(target);
    if (st.eta_seconds >= 0 || st.headers_per_sec > 0) s += " · " + format_eta(st.eta_seconds);
    return s;
  }
  if (st.phase == SyncStatus::Phase::Watching) {
    return "blocks " + std::to_string(st.tip_height) + "/" +
           std::to_string(target ? target : st.tip_height) + " (synced)";
  }
  if (st.phase == SyncStatus::Phase::Connecting || st.phase == SyncStatus::Phase::Reconnecting) {
    std::string s = "blocks " + std::to_string(st.tip_height) + "/" +
                    (target ? std::to_string(target) : std::string("…"));
    if (st.eta_seconds >= 0) s += " · " + format_eta(st.eta_seconds);
    return s;
  }
  return "blocks " + std::to_string(st.tip_height);
}

BackgroundSync::BackgroundSync() = default;

BackgroundSync::~BackgroundSync() { stop(); }

void BackgroundSync::set_phase(SyncStatus::Phase p, const std::string& detail) {
  std::lock_guard<std::mutex> lock(status_mu_);
  status_.phase = p;
  if (!detail.empty()) status_.detail = detail;
  status_.running = running_.load();
}

void BackgroundSync::reset_rate() {
  rate_sample_height_ = 0;
  rate_ema_ = 0;
  std::lock_guard<std::mutex> lock(status_mu_);
  status_.headers_per_sec = 0;
  status_.eta_seconds = -1;
}

void BackgroundSync::refresh_eta_locked() {
  uint32_t target = status_.target_height;
  if (target == 0 && status_.peer_height > 0) target = static_cast<uint32_t>(status_.peer_height);
  if (target > status_.tip_height && status_.headers_per_sec > 10.0) {
    status_.eta_seconds =
        static_cast<int64_t>((target - status_.tip_height) / status_.headers_per_sec);
  } else if (target <= status_.tip_height) {
    status_.eta_seconds = 0;
  } else {
    status_.eta_seconds = -1;
  }
}

void BackgroundSync::update_tip(uint32_t height, const Hash256& tip) {
  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(status_mu_);
  if (rate_sample_height_ > 0 && height > rate_sample_height_) {
    double dt = std::chrono::duration<double>(now - rate_sample_time_).count();
    if (dt >= 0.25) {
      double inst = static_cast<double>(height - rate_sample_height_) / dt;
      rate_ema_ = (rate_ema_ > 0.0) ? (rate_ema_ * 0.65 + inst * 0.35) : inst;
      status_.headers_per_sec = rate_ema_;
      rate_sample_height_ = height;
      rate_sample_time_ = now;
    }
  } else if (height != rate_sample_height_) {
    rate_sample_height_ = height;
    rate_sample_time_ = now;
  }
  status_.tip_height = height;
  status_.tip_hash = to_hex(tip.data(), tip.size(), true);
  if (status_.target_height < height) status_.target_height = height;
  refresh_eta_locked();
}

net::BloomFilter BackgroundSync::build_bloom_locked() {
  // caller holds wallet_mu_
  auto scripts = wallet_->watched_scripts();
  uint32_t n = static_cast<uint32_t>(std::max<size_t>(scripts.size() * 2 + 16, 128));
  net::BloomFilter bloom(n, 0.0001, random_u32(), net::BLOOM_UPDATE_ALL);
  wallet_->fill_bloom(bloom);
  return bloom;
}

void BackgroundSync::start(Wallet* wallet, const std::string& password) {
  if (!wallet) return;
  if (running_.load()) return;
  stop();
  wallet_ = wallet;
  password_ = password;
  data_dir_ = wallet->data_dir();
  stop_ = false;
  pause_ = false;
  bloom_dirty_ = true;
  running_ = true;
  set_error_log_dir(data_dir_);
  {
    std::lock_guard<std::mutex> lock(status_mu_);
    status_ = SyncStatus{};
    status_.running = true;
    status_.phase = SyncStatus::Phase::Connecting;
    status_.detail = "starting background sync";
    status_.balance_sats = wallet_->balance();
  }
  thread_ = std::thread([this] { thread_main(); });
}

void BackgroundSync::stop() {
  stop_ = true;
  pause_ = false;
  if (thread_.joinable()) thread_.join();
  running_ = false;
  set_phase(SyncStatus::Phase::Stopped, "sync stopped");
  wallet_ = nullptr;
}

void BackgroundSync::pause() {
  pause_ = true;
  set_phase(SyncStatus::Phase::Paused, "paused for wallet operation");
}

void BackgroundSync::resume() {
  pause_ = false;
  bloom_dirty_ = true;
}

void BackgroundSync::request_bloom_refresh() { bloom_dirty_ = true; }

SyncStatus BackgroundSync::status() const {
  std::lock_guard<std::mutex> lock(status_mu_);
  return status_;
}

void BackgroundSync::thread_main() {
  while (!stop_.load()) {
    try {
      while (pause_.load() && !stop_.load()) {
        set_phase(SyncStatus::Phase::Paused, "paused");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
      if (stop_.load()) break;

      set_phase(SyncStatus::Phase::Connecting, "dialing Litecoin P2P peers");
      reset_rate();
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.connected = false;
        status_.conn_status = "connecting";
        status_.peers = 0;
      }
      auto spv = std::make_unique<net::SpvNode>(data_dir_);
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.tip_height = spv->tip_height();
        status_.tip_hash = to_hex(spv->tip_hash().data(), spv->tip_hash().size(), true);
        rate_sample_height_ = status_.tip_height;
        rate_sample_time_ = std::chrono::steady_clock::now();
      }
      if (!spv->connect_peers(1, 2)) throw std::runtime_error("no peers available");
      // New peer session — always push bloom again (dirty may be false after prior watch).
      bloom_dirty_ = true;

      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.peers = static_cast<int>(spv->peer_count());
        status_.connected = true;
        status_.conn_status = "connected";
        if (auto* p = spv->active_peer()) {
          status_.peer_height = p->peer_start_height();
          if (status_.peer_height > 0)
            status_.target_height = static_cast<uint32_t>(status_.peer_height);
          status_.peer_agent = p->peer_user_agent();
          status_.detail = "peers " + std::to_string(spv->peer_count()) + " · " + status_.peer_agent;
          refresh_eta_locked();
        }
      }

      auto on_progress = [this](uint32_t height, const Hash256& tip) {
        update_tip(height, tip);
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.connected = true;
        status_.conn_status = "connected";
        if (status_.headers_per_sec > 0) {
          status_.detail = "height " + std::to_string(height) + " · " +
                           std::to_string(static_cast<int>(status_.headers_per_sec + 0.5)) +
                           " hdr/s · " + format_eta(status_.eta_seconds);
        } else {
          status_.detail = "height " + std::to_string(height);
        }
      };

      set_phase(SyncStatus::Phase::SyncingHeaders, "downloading block headers");
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.conn_status = "connected";
        status_.connected = true;
      }
      int stall_retries = 0;
      while (!stop_.load()) {
        while (pause_.load() && !stop_.load()) {
          spv->flush_headers();
          set_phase(SyncStatus::Phase::Paused, "paused");
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (stop_.load()) break;
        int r = spv->sync_headers_round(on_progress, &stop_);
        {
          std::lock_guard<std::mutex> slock(status_mu_);
          status_.tip_height = spv->tip_height();
          status_.tip_hash = to_hex(spv->tip_hash().data(), spv->tip_hash().size(), true);
          status_.connected = true;
          status_.conn_status = "connected";
          status_.peers = static_cast<int>(spv->peer_count());
          if (auto* p = spv->active_peer()) {
            status_.peer_agent = p->peer_user_agent();
            status_.peer_height = p->peer_start_height();
          }
          refresh_eta_locked();
          if (wallet_) {
            // cheap unlocked peek avoided — balance updated less often
          }
        }
        if (r == 1) {
          stall_retries = 0;
          continue;  // full speed — immediately request next batch
        }
        if (r == -1) {
          ++stall_retries;
          if (stall_retries >= 8) throw std::runtime_error("header sync stalled; rotating peer");
          continue;
        }
        // r == 0 caught up
        spv->flush_headers();
        break;
      }
      if (stop_.load()) {
        spv->flush_headers();
        break;
      }

      {
        std::lock_guard<std::mutex> wlock(wallet_mu_);
        std::lock_guard<std::mutex> slock(status_mu_);
        if (wallet_) status_.balance_sats = wallet_->balance();
      }

      // Catch up: bloom-rescan headers we already have but never filtered.
      {
        bloom_dirty_ = true;
        {
          std::lock_guard<std::mutex> wlock(wallet_mu_);
          if (!wallet_) break;
          auto bloom = build_bloom_locked();
          spv->set_bloom(bloom);
          spv->send_filterload();
        }

        uint32_t from = 0;
        uint32_t tip = spv->tip_height();
        {
          std::lock_guard<std::mutex> wlock(wallet_mu_);
          if (wallet_) from = wallet_->filter_height();
        }
  // First run: scan a recent window (covers payments mined during header sync).
        // Full-block fallback is capped at 128; bloom peers can do more.
        constexpr uint32_t kFirstWindow = 500;
        if (from == 0 && tip > kFirstWindow) from = tip - kFirstWindow;
        else if (from == 0) from = 0;

        if (from < tip) {
          set_phase(SyncStatus::Phase::Watching, "rescanning filtered blocks");
          {
            std::lock_guard<std::mutex> lock(status_mu_);
            status_.rescanning = true;
            status_.rescan_height = from;
            status_.tip_height = tip;
            status_.detail = "rescan " + std::to_string(from) + ".." + std::to_string(tip);
          }
          auto rescan_progress = [this, tip](uint32_t height, const Hash256&) {
            std::lock_guard<std::mutex> lock(status_mu_);
            status_.rescanning = true;
            status_.rescan_height = height;
            status_.tip_height = tip;
            status_.detail = "rescan " + std::to_string(height) + "/" + std::to_string(tip);
          };
          auto on_tx = [this](const Transaction& tx, uint32_t height, const Hash256&) {
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            if (!wallet_) return;
            wallet_->ingest_tx(tx, height);
            try {
              wallet_->save(password_);
            } catch (const std::exception& e) {
              log_error(e.what(), "background_sync/save");
            } catch (...) {
              log_error("wallet save failed", "background_sync/save");
            }
            {
              std::lock_guard<std::mutex> slock(status_mu_);
              status_.matched_txs += 1;
              status_.balance_sats = wallet_->balance();
              status_.detail = "matched tx at height " + std::to_string(height);
            }
            bloom_dirty_ = true;
          };
          uint32_t scanned =
              spv->rescan_filtered(from, on_tx, rescan_progress, &stop_);
          {
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            if (wallet_) wallet_->set_filter_height(scanned);
          }
          {
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            std::lock_guard<std::mutex> lock(status_mu_);
            status_.rescanning = false;
            status_.rescan_height = scanned;
            if (wallet_) status_.balance_sats = wallet_->balance();
          }
        }
      }
      if (stop_.load()) {
        spv->flush_headers();
        break;
      }

      // Continuous watch loop — never exits except stop/error.
      set_phase(SyncStatus::Phase::Watching, "headers caught up; watching for wallet txs");
      // Ensure bloom is installed before the first poll (reconnect-safe).
      bloom_dirty_ = true;
      while (!stop_.load()) {
        while (pause_.load() && !stop_.load()) {
          set_phase(SyncStatus::Phase::Paused, "paused");
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (stop_.load()) break;

        if (bloom_dirty_.exchange(false) || !spv->has_bloom()) {
          try {
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            if (!wallet_) break;
            auto bloom = build_bloom_locked();
            spv->set_bloom(bloom);
            spv->send_filterload();
            set_phase(SyncStatus::Phase::Watching, "bloom filter refreshed");
          } catch (const std::exception& e) {
            bloom_dirty_ = true;
            throw;
          }
        }

        spv->poll_network(
            [this](const Transaction& tx, uint32_t height, const Hash256&) {
              std::lock_guard<std::mutex> wlock(wallet_mu_);
              if (!wallet_) return;
              wallet_->ingest_tx(tx, height);
              try {
                wallet_->save(password_);
              } catch (const std::exception& e) {
                log_error(e.what(), "background_sync/save");
              } catch (...) {
                log_error("wallet save failed", "background_sync/save");
              }
              {
                std::lock_guard<std::mutex> slock(status_mu_);
                status_.matched_txs += 1;
                status_.balance_sats = wallet_->balance();
                status_.detail = "matched tx at height " + std::to_string(height);
              }
              bloom_dirty_ = true;
            },
            on_progress, 15000, &stop_);

        // Keep headers advancing even while watching.
        if (!stop_.load() && !pause_.load()) {
          set_phase(SyncStatus::Phase::SyncingHeaders, "checking for new headers");
          int stall = 0;
          while (!stop_.load() && !pause_.load()) {
            int r = spv->sync_headers_round(on_progress, &stop_);
            if (r == 1) {
              stall = 0;
              continue;
            }
            if (r == -1) {
              if (++stall >= 5) break;
              continue;
            }
            break;
          }
          spv->flush_headers();

          // Filter any newly synced headers we haven't scanned yet.
          uint32_t from = 0;
          uint32_t tip = spv->tip_height();
          {
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            if (wallet_) from = wallet_->filter_height();
          }
          if (from < tip && !stop_.load() && !pause_.load()) {
            auto on_tx = [this](const Transaction& tx, uint32_t height, const Hash256&) {
              std::lock_guard<std::mutex> wlock(wallet_mu_);
              if (!wallet_) return;
              wallet_->ingest_tx(tx, height);
              try {
                wallet_->save(password_);
              } catch (...) {
              }
              {
                std::lock_guard<std::mutex> slock(status_mu_);
                status_.matched_txs += 1;
                status_.balance_sats = wallet_->balance();
              }
              bloom_dirty_ = true;
            };
            uint32_t scanned = spv->rescan_filtered(from, on_tx, on_progress, &stop_);
            std::lock_guard<std::mutex> wlock(wallet_mu_);
            if (wallet_) wallet_->set_filter_height(scanned);
          }

          set_phase(SyncStatus::Phase::Watching, "live / watching mempool+blocks");
        }

        {
          std::lock_guard<std::mutex> wlock(wallet_mu_);
          std::lock_guard<std::mutex> slock(status_mu_);
          if (wallet_) status_.balance_sats = wallet_->balance();
          status_.tip_height = spv->tip_height();
          status_.tip_hash = to_hex(spv->tip_hash().data(), spv->tip_hash().size(), true);
          status_.peers = static_cast<int>(spv->peer_count());
          if (auto* p = spv->active_peer()) {
            status_.peer_agent = p->peer_user_agent();
            status_.peer_height = p->peer_start_height();
          }
        }
      }
    } catch (const std::exception& e) {
      log_error(e.what(), "background_sync");
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.phase = SyncStatus::Phase::Error;
        status_.last_error = e.what();
        status_.detail = e.what();
        status_.connected = false;
        status_.conn_status = "disconnected";
        status_.peers = 0;
      }
      set_phase(SyncStatus::Phase::Reconnecting, std::string("retry in 2s: ") + e.what());
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.conn_status = "reconnecting";
      }
      for (int i = 0; i < 20 && !stop_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } catch (...) {
      log_error("unknown non-std exception", "background_sync");
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.phase = SyncStatus::Phase::Error;
        status_.last_error = "unknown exception";
        status_.detail = "unknown exception";
        status_.connected = false;
        status_.conn_status = "disconnected";
        status_.peers = 0;
      }
      set_phase(SyncStatus::Phase::Reconnecting, "retry in 2s: unknown exception");
      {
        std::lock_guard<std::mutex> lock(status_mu_);
        status_.conn_status = "reconnecting";
      }
      for (int i = 0; i < 20 && !stop_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  running_ = false;
  set_phase(SyncStatus::Phase::Stopped, "sync thread exited");
}

}  // namespace ltc
