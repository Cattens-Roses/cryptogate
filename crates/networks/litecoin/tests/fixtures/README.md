`mainnet-4032.dat` contains Litecoin mainnet headers 1 through 4032, exactly 80 bytes each, copied from the supplied C++ example's public blockchain header cache (`ltcengine/testdata/synctest/headers.dat`). It contains no wallet material.

The historical regression validates all Scrypt proofs, chain links, timestamps, and expected difficulty through the first two retargets. Height 4032 must match the Litecoin Core checkpoint `9ce90e427198fc0ef05e5905ce3503725b80e26afd35a987965fd7e3d9cf0846`.
