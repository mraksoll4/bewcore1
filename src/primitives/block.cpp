// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

/* yespower algo */

#include <crypto/yespower-1.0.1/yespower.h>
#include <streams.h>
#include <version.h>
#include <stdlib.h> // exit()
#include <sync.h>

uint256 CBlockHeaderUncached::GetHash() const
{
    return (CHashWriter{PROTOCOL_VERSION} << *this).GetHash();
}

/* YespowerSugar */
uint256 CBlockHeaderUncached::GetPoWHash() const
{
    static const yespower_params_t yespower_1_0_sugarchain = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = NULL,
        .perslen = 0
    };
    uint256 hash;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    if (yespower_tls((const uint8_t *)&ss[0], ss.size(), &yespower_1_0_sugarchain, (yespower_binary_t *)&hash)) {
        tfm::format(std::cerr, "Error: CBlockHeaderUncached::GetPoWHash(): failed to compute PoW hash (out of memory?)\n");
        exit(1);
    }
    return hash;
}

/* YespowerSugar */
uint256 CBlockHeader::GetPoWHash_cached() const
{
    uint256 block_hash = GetHash();
    LOCK(cache_lock);
    if (cache_init) {
        if (block_hash != cache_block_hash) {
            tfm::format(std::cerr, "Error: CBlockHeader::GetPoWHash_cached(): block hash changed unexpectedly\n");
            exit(1);
        }
        /* yespower PoW cache log: O (cyan) = HIT */
        // printf("\033[36;1mO\033[0m block = %s PoW = %s\n", cache_block_hash.ToString().c_str(), cache_PoW_hash.ToString().c_str());
    } else {
        cache_PoW_hash = GetPoWHash();
        cache_block_hash = block_hash;
        cache_init = true;
        /* yespower PoW cache log: x = MISS */
        // printf("x block = %s PoW = %s\n", cache_block_hash.ToString().c_str(), cache_PoW_hash.ToString().c_str());
    }
    return cache_PoW_hash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
