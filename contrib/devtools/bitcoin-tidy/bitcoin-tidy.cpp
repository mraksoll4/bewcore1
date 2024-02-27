// Copyright (c) 2023 Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "logprintf.h"

#include <clang-tidy/ClangTidyModule.h>
#include <clang-tidy/ClangTidyModuleRegistry.h>

class BitcoinModule final : public clang::tidy::ClangTidyModule
{
public:
    void addCheckFactories(clang::tidy::ClangTidyCheckFactories& CheckFactories) override
    {
        CheckFactories.registerCheck<bewcore::LogPrintfCheck>("bewcore-unterminated-logprintf");
    }
};

static clang::tidy::ClangTidyModuleRegistry::Add<BitcoinModule>
    X("bewcore-module", "Adds bewcore checks.");

volatile int BitcoinModuleAnchorSource = 0;
