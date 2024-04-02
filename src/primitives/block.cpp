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

#include <crypto/argon2d/argon2.h>
#include <crypto/argon2d/blake2/blake2.h>

static const size_t OUTPUT_BYTES = 32;
static const unsigned int DEFAULT_ARGON2_FLAG = 2;

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
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    if (yespower_tls((const uint8_t *)&ss[0], ss.size(), &yespower_1_0_bewcore, (yespower_binary_t *)&hash)) {
        tfm::format(std::cerr, "Error: CBlockHeaderUncached::GetPoWHash(): failed to compute PoW hash (out of memory?)\n");
        exit(1);
    }
    return hash;
}

uint256 CBlockHeader::GetPoWHash2() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    return CustomHash(ss);
}


// Функция для вычисления хеша Argon2id
int GetArgon2idHash(const void* in, size_t size, void* out) {
    argon2_context context;
    context.out = (uint8_t*)out;
    context.outlen = OUTPUT_BYTES;
    context.pwd = (uint8_t*)in;
    context.pwdlen = size;
    context.salt = (uint8_t*)in; //salt = input
    context.saltlen = size;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG; // = ARGON2_DEFAULT_FLAGS
    // main configurable Argon2 hash parameters
    context.m_cost = 500; // Memory in KiB (512KB)
    context.lanes = 8;    // Degree of Parallelism
    context.threads = 1;  // Threads
    context.t_cost = 2;   // Iterations
    
    // Вычисление хеша Argon2id
    int rc = argon2_ctx(&context, Argon2_id);
    if (ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    
    return rc; // Возвращаем код завершения Argon2
}

// Функция для получения хэша Argon2id из блока
uint256 CBlockHeader::GetArgon2idPoWHash() const {
    uint256 hashResult;
    int rc = GetArgon2idHash(this, sizeof(*this), &hashResult);
    if (ARGON2_OK != rc) {
        printf("Error: Failed to compute Argon2id hash\n");
        exit(1);
    }
    return hashResult;
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
