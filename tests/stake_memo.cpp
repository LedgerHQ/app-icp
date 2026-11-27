/*******************************************************************************
 *   (c) 2026 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <hexutils.h>
#include <parser.h>

#include <array>
#include <cstring>

#include "gtest/gtest.h"
#include "parser_impl.h"

namespace {

// ICRC-1 neuron stake with the 8-byte big-endian memo 255, as the NNS dapp sends it.
const char *kStakeMemo8 =
    "d9d9f7a167636f6e74656e74a663617267588a4449444c066d7b6e006c02b3b0dac30368ad86ca8305016e7d6e786c06fbca0102c6fcb602"
    "03ba89e5c20401a2de94eb060182f3f3910c04d8a38ca80d7d0105010a0000000000000001010101209f119de3ab9caa1aca8b07a22b6156"
    "49b72c3aa6922cbf5cdba5e578afc5804b01b0ea01010800000000000000ff0001003398164aae3f17c082d43e6b63616e69737465725f69"
    "644a000000000000000201016e696e67726573735f6578706972791b178a8ba59babb8006b6d6574686f645f6e616d656e69637263315f74"
    "72616e736665726c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a1"
    "37abaa6a82e302";

// The same stake with the 1-byte memo 0xff, its subaccount hashed over that one byte.
// It reviews exactly like the one above, but governance can never claim the subaccount.
const char *kStakeMemo1 =
    "d9d9f7a167636f6e74656e74a66361726758834449444c066d7b6e006c02b3b0dac30368ad86ca8305016e7d6e786c06fbca0102c6fcb602"
    "03ba89e5c20401a2de94eb060182f3f3910c04d8a38ca80d7d0105010a000000000000000101010120b5605765d607991851290a50c73b9c"
    "f98feb13217987290d83e30d4c45eaea4a01b0ea010101ff0001003398164aae3f17c082d43e6b63616e69737465725f69644a0000000000"
    "00000201016e696e67726573735f6578706972791b178a8ba59babb8006b6d6574686f645f6e616d656e69637263315f7472616e73666572"
    "6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302";

parser_error_t ValidateStake(const char *hex) {
    static std::array<uint8_t, 4096> buffer{};
    std::memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));
    const auto len = parseHexString(buffer.data(), buffer.size(), hex);
    parser_context_t ctx{};
    EXPECT_EQ(parser_parse(&ctx, buffer.data(), len), parser_ok);
    // P2 = 1 on INIT
    parser_tx_obj.special_transfer_type = neuron_stake_transaction;
    return parser_validate(&ctx);
}

TEST(StakeMemo, EightByteMemoIsAccepted) { EXPECT_EQ(ValidateStake(kStakeMemo8), parser_ok); }

TEST(StakeMemo, ShorterMemoIsRefused) { EXPECT_EQ(ValidateStake(kStakeMemo1), parser_invalid_address); }

}  // namespace
