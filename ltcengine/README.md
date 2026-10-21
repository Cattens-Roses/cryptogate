# ltcengine

Litecoin SPV wallet CLI in C++. Talks to the Litecoin P2P network only — no explorers, Electrum servers, or other third-party APIs.

## Features

- **Offline-capable keys**: BIP39 mnemonic, BIP32 HD, encrypted wallet file (AES-256-CBC + PBKDF2)
- **Address types**: legacy P2PKH (`L…`), nested SegWit P2SH-P2WPKH (`M…`), native SegWit P2WPKH (`ltc1q…`), Taproot P2TR (`ltc1p…`)
- **Send to any standard address**: P2PKH / P2SH / P2WPKH / P2WSH / P2TR
- **Pruned SPV sync**: header chain + BIP37 bloom filter; downloads only merkleblocks / txs matching your wallet (not the full blockchain)

## Build

Requirements: CMake ≥ 3.16, C++17 compiler, Git (for libsecp256k1 FetchContent).

### Windows (MSVC)

```bat
build.bat
run.bat
```

Binary: `bin\ltcengine.exe` (plus `libsecp256k1-2.dll`).

### Linux / WSL

```bash
# Ubuntu/Debian WSL — one-time deps
sudo apt update
sudo apt install -y build-essential cmake git

chmod +x build.sh run.sh
./build.sh
./run.sh                 # TUI
./run.sh connect ./wallet
```

Binary: `bin/ltcengine` (libsecp256k1 linked statically). Uses `build-linux/` so it does not overwrite the Windows `build/` tree when the repo lives on the Windows filesystem.

Manual CMake:

```bash
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j$(nproc)
```

## Usage

Interactive TUI (default when run with no args):

```bash
ltcengine
ltcengine tui ./mywallet
```

The TUI starts **continuous background P2P sync** when a wallet is opened. A live status panel shows phase, tip height, balance, peers, and matched txs while you use the menu.

Commands:

```text
ltcengine create <datadir> <password>
ltcengine import <datadir> <password> <mnemonic words...>
ltcengine address <datadir> <password> [native|legacy|nested|taproot]
ltcengine balance <datadir> <password>
ltcengine sync <datadir> <password>
ltcengine send <datadir> <password> <to> <amount_sats> [fee_sat_vb]
```

Example:

```bash
ltcengine create ./mywallet "strong-pass"
ltcengine address ./mywallet "strong-pass" native
ltcengine sync ./mywallet "strong-pass"
ltcengine send ./mywallet "strong-pass" ltc1q... 100000 10
```

## How sync works

1. Resolve Litecoin DNS seeds and connect to peers on port **9333**
2. Download **block headers only** (persisted in `headers.dat`)
3. Load a BIP37 bloom filter with your watched scripts / UTXOs
4. Request **filtered merkleblocks** and matching transactions only

Initial header sync can take a while on first run (~2M+ headers). Later runs resume from `headers.dat`.

## Notes

- Fee rate is sats per vbyte (default 10)
- Change is sent to a native SegWit address from the wallet
- Backup the mnemonic printed by `create`; password encrypts the on-disk seed
