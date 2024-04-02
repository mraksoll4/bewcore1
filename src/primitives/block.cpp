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

// Функция для получения хэша с использованием Argon2id
uint256 GetArgon2idHash(const void* input, size_t input_size) {
    argon2_context context;
    context.out = (uint8_t*)malloc(OUTPUT_BYTES); // Мы выделяем память для хранения хэша
    context.outlen = OUTPUT_BYTES;
    context.pwd = (uint8_t*)input;
    context.pwdlen = input_size;
    context.salt = (uint8_t*)input; // Можно использовать input как соль, но лучше использовать случайную соль
    context.saltlen = input_size;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG;
    context.m_cost = 500; // Примерная настройка параметров Argon2
    context.lanes = 8;
    context.threads = 1;
    context.t_cost = 2;

    int result = argon2_ctx(&context, Argon2_id); // Используем Argon2id здесь
    if (result != ARGON2_OK) {
        // Обработка ошибок, если необходимо
    }

    // Преобразуем полученный хэш в uint256 и возвращаем
    uint256 hash;
    memcpy(&hash, context.out, sizeof(hash));
    free(context.out); // Освобождаем память, выделенную для хэша
    return hash;
}

// Функция для получения хэша Argon2id из блока
uint256 CBlockHeader::GetArgon2idPoWHash() const {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    return GetArgon2idHash((const uint8_t*)&ss[0], ss.size());
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
