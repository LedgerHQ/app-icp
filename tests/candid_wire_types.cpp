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

// The canisters decode a Candid argument with subtyping: a record may carry
// fields they skip or lack opt fields they read as null, and an `opt T` whose
// `T` does not match decodes as null with its bytes skipped by `T`. The Candid
// parser used to check only the outer constructor of each type and then read a
// fixed layout, so a host could build a wire type under which the device showed
// one spender, destination, amount, subaccount or memo and the canister used
// another (ICP-016, ICP-017).
//
// candid_wire_types.json holds:
// - requests as real clients encode them (@dfinity/nns, @dfinity/sns,
//   @dfinity/ledger-icp, @dfinity/ledger-icrc, @icp-sdk/canisters, Ledger
//   Live, Rust `candid` as dfx and ic-agent use it) and well-typed base requests
//   for every method, which must still be accepted and shown as before;
// - the audit's proof-of-concept envelopes and, per method, variants of a base
//   request that change one part of the wire type or one flag byte (built by
//   candid_wire_types_gen.py), which must be refused.

#include <hexutils.h>
#include <parser.h>

#include <cstring>
#include <vector>

#include "candid/candid_helper.h"
#include "common.h"
#include "gtest/gtest.h"
#include "parser_impl.h"

namespace {

class JsonTests_CandidWireTypes : public JsonTests_Base {};

INSTANTIATE_TEST_SUITE_P(CandidWireTypes, JsonTests_CandidWireTypes,
                         ::testing::ValuesIn(GetJsonTestCases("candid_wire_types.json")),
                         JsonTests_CandidWireTypes::PrintToStringParamName());

TEST_P(JsonTests_CandidWireTypes, Normal) { check_testcase(GetParam(), false); }

TEST_P(JsonTests_CandidWireTypes, Expert) { check_testcase(GetParam(), true); }

// A refused vector must be refused while its argument is parsed, not by a later
// check that happens to fail on it.
TEST(CandidWireTypes, RefusedWhileParsingTheArgument) {
    const auto cases = GetJsonTestCases("candid_wire_types.json");
    ASSERT_FALSE(cases.empty());

    size_t refused = 0;
    for (const auto &tc : cases) {
        if (tc.valid) {
            continue;
        }
        SCOPED_TRACE(tc.name);
        std::vector<uint8_t> buffer(tc.blob.size() / 2);
        const auto len = parseHexString(buffer.data(), buffer.size(), tc.blob.c_str());
        parser_context_t ctx{};
        std::memset(&parser_tx_obj, 0, sizeof(parser_tx_obj));
        EXPECT_NE(parser_parse(&ctx, buffer.data(), len), parser_ok);
        refused++;
    }
    EXPECT_GT(refused, 0u);
}

parser_context_t Context(const std::vector<uint8_t> &bytes) {
    parser_context_t ctx{};
    ctx.buffer = bytes.data();
    ctx.bufferLen = static_cast<uint16_t>(bytes.size());
    return ctx;
}

// The canisters refuse an opt or bool byte other than 0 or 1.
TEST(CandidWireTypes, OptAndBoolFlagsAreZeroOrOne) {
    for (const uint8_t b : {0, 1}) {
        const std::vector<uint8_t> bytes = {b};
        auto ctx = Context(bytes);
        uint8_t v = 0xAA;
        ASSERT_EQ(readCandidOptFlag(&ctx, &v), parser_ok);
        EXPECT_EQ(v, b);
        ctx = Context(bytes);
        ASSERT_EQ(readCandidBool(&ctx, &v), parser_ok);
        EXPECT_EQ(v, b);
    }
    for (const uint8_t b : {2, 0x80, 0xFF}) {
        SCOPED_TRACE(b);
        const std::vector<uint8_t> bytes = {b};
        auto ctx = Context(bytes);
        uint8_t v = 0;
        EXPECT_NE(readCandidOptFlag(&ctx, &v), parser_ok);
        ctx = Context(bytes);
        EXPECT_NE(readCandidBool(&ctx, &v), parser_ok);
    }
}

// A principal is reference tag 1, a LEB128 length of at most 29, the bytes.
TEST(CandidWireTypes, PrincipalReference) {
    candid_Principal_t p{};

    std::vector<uint8_t> ok = {0x01, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01};
    auto ctx = Context(ok);
    ASSERT_EQ(readCandidPrincipal(&ctx, &p), parser_ok);
    EXPECT_EQ(p.len, 10);
    EXPECT_EQ(ctx.offset, ok.size());

    // Opaque reference
    std::vector<uint8_t> opaque = {0x00};
    ctx = Context(opaque);
    EXPECT_NE(readCandidPrincipal(&ctx, &p), parser_ok);

    std::vector<uint8_t> badTag = {0x02, 0x00};
    ctx = Context(badTag);
    EXPECT_NE(readCandidPrincipal(&ctx, &p), parser_ok);

    std::vector<uint8_t> tooLong(2 + 30, 0x00);
    tooLong[0] = 0x01;
    tooLong[1] = 30;
    ctx = Context(tooLong);
    EXPECT_NE(readCandidPrincipal(&ctx, &p), parser_ok);
}

// The type checks compare structure, not table positions: the same type is
// accepted whatever order an encoder lays the table out in.
TEST(CandidWireTypes, TypeChecksAreStructural) {
    // 0: record { owner : principal; subaccount : opt blob } as
    //    table 0 = opt 1, 1 = vec nat8, 2 = record {...}
    // 1: the same type as 0 = vec nat8, 1 = opt 0, 2 = record {...}
    const std::vector<std::vector<uint8_t>> tables = {
        {0x03, 0x6E, 0x01, 0x6D, 0x7B, 0x6C, 0x02, 0xB3, 0xB0, 0xDA, 0xC3, 0x03, 0x68, 0xAD, 0x86, 0xCA, 0x83, 0x05, 0x00},
        {0x03, 0x6D, 0x7B, 0x6E, 0x00, 0x6C, 0x02, 0xB3, 0xB0, 0xDA, 0xC3, 0x03, 0x68, 0xAD, 0x86, 0xCA, 0x83, 0x05, 0x01},
    };
    for (const auto &table : tables) {
        parser_tx_t tx{};
        tx.candid_typetableSize = 3;
        candid_transaction_t txn{};
        txn.ctx.buffer = table.data();
        txn.ctx.bufferLen = static_cast<uint16_t>(table.size());
        txn.ctx.tx_obj = &tx;
        txn.types_entry_point = 1;

        const uint64_t fields[] = {947296307 /* owner */, 1349681965 /* subaccount */};
        int64_t types[2] = {0};
        ASSERT_EQ(candidExpectRecord(&txn, 2, fields, 2, types), parser_ok);
        EXPECT_EQ(candidExpectPrimitive(types[0], Principal), parser_ok);
        EXPECT_EQ(candidExpectOptBlob(&txn, types[1]), parser_ok);

        // the same record does not pass for any other shape
        EXPECT_NE(candidExpectRecord(&txn, 2, fields, 1, types), parser_ok);
        const uint64_t renamed[] = {947296307, 1349681966};
        EXPECT_NE(candidExpectRecord(&txn, 2, renamed, 2, types), parser_ok);
        EXPECT_NE(candidExpectOptOf(&txn, types[1], Nat8), parser_ok);
        EXPECT_NE(candidExpectBlob(&txn, types[1]), parser_ok);
        EXPECT_NE(candidExpectPrimitive(types[0], Text), parser_ok);
        // a primitive opcode never names a table entry
        EXPECT_NE(candidExpectOptBlob(&txn, Principal), parser_ok);
        // an index past the table
        EXPECT_NE(candidExpectOptBlob(&txn, 3), parser_ok);
    }
}

}  // namespace
