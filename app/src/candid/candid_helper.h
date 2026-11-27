/*******************************************************************************
 *   (c) 2018 - 2023s Zondax AG
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <zxerror.h>
#include <zxmacros.h>

#include "candid_types.h"
#include "parser_common.h"

typedef struct {
    uint64_t variant_index;
    uint64_t field_hash;
    int64_t implementation;
} candid_element_t;

typedef struct {
    uint16_t types_entry_point;
    parser_context_t ctx;
    int64_t txn_type;
    uint64_t txn_length;
    candid_element_t element;
} candid_transaction_t;

parser_error_t readCandidLEB128(parser_context_t *ctx, uint64_t *v);
parser_error_t readCandidSLEB128(parser_context_t *ctx, int64_t *v);

parser_error_t readCandidHeader(parser_context_t *ctx, candid_transaction_t *txn);
parser_error_t readAndCheckRootType(parser_context_t *ctx);

parser_error_t readCandidNat(parser_context_t *ctx, uint64_t *v);
parser_error_t readCandidNat32(parser_context_t *ctx, uint32_t *v);
parser_error_t readCandidNat64(parser_context_t *ctx, uint64_t *v);

parser_error_t readCandidInt32(parser_context_t *ctx, int32_t *v);

parser_error_t readCandidRecordLength(candid_transaction_t *txn);
parser_error_t readCandidByte(parser_context_t *ctx, uint8_t *v);
parser_error_t readCandidVecLength(parser_context_t *ctx, uint8_t *len);
parser_error_t readCandidBytes(parser_context_t *ctx, uint8_t *buff, uint8_t buffLen);

parser_error_t readCandidText(parser_context_t *ctx, sizedBuffer_t *v);

parser_error_t readCandidInnerElement(candid_transaction_t *txn, candid_element_t *element);

parser_error_t readCandidType(parser_context_t *ctx, int64_t *t);
parser_error_t readCandidTypeTable_Item(parser_context_t *ctx, const int64_t *type, __Z_UNUSED uint64_t typeIdx);

parser_error_t getCandidTypeFromTable(candid_transaction_t *txn, uint64_t table_index);

// Strict wire-type checks.
//
// The canisters decode an argument with Candid subtyping: a record may carry
// fields they skip or lack opt fields they read as null, and an `opt T` whose
// `T` does not match decodes as null with its bytes skipped by `T`. A wire type
// that only resembles the expected one therefore makes the canister and this
// parser read different values from the same bytes. Each function below accepts
// exactly one type from the canister's .did and refuses everything else.
//
// `type` is a type reference as found in the type table: a primitive opcode
// (negative) or the index of a table entry. The comparison is structural, so
// encoders that order the table differently are all accepted.
parser_error_t candidExpectPrimitive(int64_t type, IDLTypes_e primitive);
parser_error_t candidExpectOpt(candid_transaction_t *txn, int64_t type, int64_t *inner);
parser_error_t candidExpectOptOf(candid_transaction_t *txn, int64_t type, IDLTypes_e primitive);
parser_error_t candidExpectVec(candid_transaction_t *txn, int64_t type, int64_t *element);
parser_error_t candidExpectVecOf(candid_transaction_t *txn, int64_t type, IDLTypes_e primitive);
// blob = vec nat8
parser_error_t candidExpectBlob(candid_transaction_t *txn, int64_t type);
parser_error_t candidExpectOptBlob(candid_transaction_t *txn, int64_t type);
// A record with exactly `count` fields whose ids are `hashes` (ascending, as on
// the wire); the type of field i is returned in `fields[i]` for the caller to check.
parser_error_t candidExpectRecord(candid_transaction_t *txn, int64_t type, const uint64_t *hashes, uint8_t count,
                                  int64_t *fields);
// A record with the single field `hash`, whose type is returned in `field`.
parser_error_t candidExpectSingleFieldRecord(candid_transaction_t *txn, int64_t type, uint64_t hash, int64_t *field);
// record { <hash> : <primitive> }, e.g. Tokens, TimeStamp, NeuronId
parser_error_t candidExpectRecordOf(candid_transaction_t *txn, int64_t type, uint64_t hash, IDLTypes_e primitive);
// record { <hash> : blob }, e.g. AccountIdentifier
parser_error_t candidExpectRecordOfBlob(candid_transaction_t *txn, int64_t type, uint64_t hash);
parser_error_t candidExpectEmptyRecord(candid_transaction_t *txn, int64_t type);
// The case a variant value selects by its wire index: its field id and type.
parser_error_t candidVariantCase(candid_transaction_t *txn, int64_t type, uint64_t index, uint64_t *hash, int64_t *caseType);

// Value readers that refuse what the canisters refuse.
// opt and bool are a single byte that is exactly 0 or 1.
parser_error_t readCandidOptFlag(parser_context_t *ctx, uint8_t *present);
parser_error_t readCandidBool(parser_context_t *ctx, uint8_t *v);
// principal: reference tag 1, LEB128 length of at most 29, bytes
parser_error_t readCandidPrincipal(parser_context_t *ctx, candid_Principal_t *principal);

#ifdef __cplusplus
}
#endif
