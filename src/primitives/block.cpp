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

uint256 CBlockHeader::GetHash() const
{
    return (CHashWriter{PROTOCOL_VERSION} << *this).GetHash();
}

/* Yespower */
uint256 CBlockHeader::GetPoWHash() const
{
    static const yespower_params_t yespower_1_0_bewcore = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = NULL,
        .perslen = 0
    };
    uint256 hash;

    // Используйте тот же способ сериализации, как и в обновленном GetHash()
    CHashWriter ss(PROTOCOL_VERSION);
    ss << *this

    if (yespower_tls((const uint8_t *)&ss[0], ss.size(), &yespower_1_0_bewcore, (yespower_binary_t *)&hash)) {
        tfm::format(std::cerr, "Error: CBlockHeader::GetPoWHash(): failed to compute PoW hash (out of memory?)\n");
        exit(1);
    }
    return hash;
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
