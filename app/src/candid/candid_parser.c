/*******************************************************************************
 *   (c) 2022 Zondax AG
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
#include "candid_parser.h"

#include "candid_helper.h"
#include "crypto.h"
#include "leb128.h"
#include "nns_parser.h"
#include "sns_parser.h"

// Good reference: https://github.com/dfinity/agent-js/tree/main/packages/candid
// https://github.com/dfinity/candid/blob/master/spec/Candid.md#deserialisation

#define MAX_FIELDS 25
#define TYPE_OPT 0
#define TYPE_NEURONS_IDS 1
#define TYPE_CALLER 2
#define ICP_CANISTER_ID_TEXTUAL "ryjl3tyaaaaaaaaaaabacai"

#define CREATE_CTX(__CTX, __TX, __INPUT, __INPUT_SIZE) \
    parser_context_t __CTX;                            \
    ctx.buffer = __INPUT;                              \
    ctx.bufferLen = __INPUT_SIZE;                      \
    ctx.offset = 0;                                    \
    ctx.tx_obj = __TX;

parser_error_t getCandidNat64FromVec(const uint8_t *buf, uint64_t *v, uint8_t size, uint8_t idx) {
    if (buf == NULL || v == NULL || idx >= size) {
        return parser_unexpected_value;
    }
    *v = 0;
    buf = buf + 8 * idx;

    for (uint8_t i = 0; i < 8; i++) {
        *v += (uint64_t)*(buf + i) << 8 * i;
    }
    return parser_ok;
}

parser_error_t getCandidInt32FromVec(const uint8_t *buf, int32_t *v, uint8_t size, uint8_t idx) {
    if (buf == NULL || v == NULL || idx >= size) {
        return parser_unexpected_value;
    }
    *v = 0;
    buf = buf + 4 * idx;

    for (uint8_t i = 0; i < 4; i++) {
        *v += (int32_t)*(buf + i) << 8 * i;
    }
    return parser_ok;
}

parser_error_t readCandidListNeurons(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))
    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    // at least we need to have the 2 non opt fields already defined in the did
    // file
    if (txn.txn_length < 2) {
        return parser_unexpected_value;
    }
    if (txn.txn_length > MAX_FIELDS) {
        return parser_too_many_fields;
    }
    uint64_t n_fields = txn.txn_length;

    // Array to save opt fields position in the record
    uint8_t opt_fields_pos[MAX_FIELDS] = {0};

    // Check types before parsing
    for (uint64_t i = 0; i < n_fields; i++) {
        // reset txn
        CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))
        CHECK_PARSER_ERR(readCandidRecordLength(&txn))
        // jump to index
        txn.element.variant_index = i;
        CHECK_PARSER_ERR(readCandidInnerElement(&txn, &txn.element))

        // element is not any of the non opt expected fields than its probably an
        // optional
        if (txn.element.field_hash == hash_neuron_ids) {
            // neuron_ids : vec nat64
            CHECK_PARSER_ERR(candidExpectVecOf(&txn, txn.element.implementation, Nat64))
            opt_fields_pos[i] = TYPE_NEURONS_IDS;
        } else if (txn.element.field_hash == hash_include_neurons_readable_by_caller && txn.element.implementation == Bool) {
            opt_fields_pos[i] = TYPE_CALLER;
        } else {
            // Any other field must be an opt, and its value null (checked below).
            // A null opt is the single byte 0 whatever its inner type, for the
            // canister as for this parser, so the inner type is not checked.
            int64_t inner = 0;
            CHECK_PARSER_ERR(candidExpectOpt(&txn, txn.element.implementation, &inner))
            opt_fields_pos[i] = TYPE_OPT;
        }
    }

    // let's read
    candid_ListNeurons_t *val = &tx->tx_fields.call.data.candid_listNeurons;
    uint64_t tmp_neuron_id = 0;
    uint8_t tmp_presence = 0;
    for (uint64_t i = 0; i < n_fields; i++) {
        // If opt_fields_pos is 0 we have a opt field in this position
        switch (opt_fields_pos[i]) {
            case TYPE_OPT:  // read the optional, expect its null or empty if not return
                            // error
                CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &tmp_presence))
                if (tmp_presence) {  // expect empty optionals
                    return parser_unexpected_value;
                }
                break;
            case TYPE_NEURONS_IDS:  // read number os ids
                CHECK_PARSER_ERR(readCandidVecLength(&ctx, &val->neuron_ids_size))

                val->neuron_ids_ptr = ctx.buffer + ctx.offset;
                for (uint8_t j = 0; j < val->neuron_ids_size; j++) {
                    CHECK_PARSER_ERR(readCandidNat64(&ctx, &tmp_neuron_id))
                }
                break;
            case TYPE_CALLER:  // read bool
                CHECK_PARSER_ERR(readCandidBool(&ctx, &val->include_neurons_readable_by_caller))
                break;
            default:
                return parser_unexpected_value;
        }
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

parser_error_t readCandidManageNeuron(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    zemu_log("readCandidManageNeuron\n");
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))

    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))

    CHECK_PARSER_ERR(getCandidTypeFromTable(&txn, tx->candid_rootType))

    CHECK_PARSER_ERR(readCandidRecordLength(&txn))
    switch (txn.txn_length) {
        case 2:  // SNS
            tx->tx_fields.call.is_sns = 1;
            return readSNSManageNeuron(&ctx, &txn);
        case 3:  // NNS
            return readNNSManageNeuron(&ctx, &txn);

        default:
            zemu_log("Error: transaction type not supported\n");
    }

    return parser_unexpected_value;
}

parser_error_t readCandidUpdateNodeProvider(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))

    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))
    candid_UpdateNodeProvider_t *val = &tx->tx_fields.call.data.candid_updateNodeProvider;

    // UpdateNodeProvider = record { reward_account : opt AccountIdentifier }
    const uint64_t fields[] = {hash_reward_account};
    int64_t types[1] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(&txn, (int64_t)tx->candid_rootType, fields, 1, types))
    int64_t accountIdentifier = 0;
    CHECK_PARSER_ERR(candidExpectOpt(&txn, types[0], &accountIdentifier))
    // AccountIdentifier = record { hash : blob }
    CHECK_PARSER_ERR(candidExpectRecordOfBlob(&txn, accountIdentifier, hash_hash))

    // Now read
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &val->has_reward_account))
    if (!val->has_reward_account) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidText(&ctx, &val->account_identifier))
    if (val->account_identifier.len != 32) {
        return parser_unexpected_number_items;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

// icrc1 Account = record { owner : principal; subaccount : opt Subaccount }, Subaccount = blob
static parser_error_t candidExpectIcrcAccount(candid_transaction_t *txn, int64_t type) {
    const uint64_t fields[] = {icrc_hash_owner, icrc_hash_subaccount};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[0], Principal))
    CHECK_PARSER_ERR(candidExpectOptBlob(txn, types[1]))
    return parser_ok;
}

static parser_error_t readCandidIcrcAccount(parser_context_t *ctx, Account_t *account) {
    CHECK_PARSER_ERR(readCandidPrincipal(ctx, &account->owner))
    account->has_owner = 1;

    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &account->has_subaccount))
    if (account->has_subaccount) {
        CHECK_PARSER_ERR(readCandidText(ctx, &account->subaccount))
    }
    return parser_ok;
}

// opt blob holding an ICRC memo, which this app shows as a u64
static parser_error_t readCandidIcrcMemo(parser_context_t *ctx, uint8_t *has_memo, sizedBuffer_t *memo) {
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, has_memo))
    if (*has_memo) {
        CHECK_PARSER_ERR(readCandidText(ctx, memo))
        // should not be bigger than uint64
        if (memo->len > 8) {
            return parser_unexpected_value;
        }
    }
    return parser_ok;
}

static parser_error_t setIcpCanister(const parser_context_t *ctx, uint8_t *icp_canister) {
    // Check if the transaction has ICP canister
    const uint8_t *canisterId = ctx->tx_obj->tx_fields.call.canister_id.data;
    const size_t canisterIdSize = ctx->tx_obj->tx_fields.call.canister_id.len;
    char canister_textual[64] = {0};
    uint16_t outLen = sizeof(canister_textual);
    if (canisterIdSize > 255) {
        return parser_unexpected_value;
    }

    crypto_principalToTextual(canisterId, (uint8_t)canisterIdSize, canister_textual, &outLen);

    *icp_canister = (strncmp(canister_textual, ICP_CANISTER_ID_TEXTUAL, sizeof(ICP_CANISTER_ID_TEXTUAL) - 1) == 0);
    return parser_ok;
}

parser_error_t readCandidICRCTransfer(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))

    // TransferArg = record {
    //   to : Account; fee : opt nat; memo : opt blob;
    //   from_subaccount : opt Subaccount; created_at_time : opt nat64; amount : nat }
    const uint64_t fields[] = {
        icrc_hash_to, icrc_hash_fee, icrc_hash_memo, icrc_hash_from_subaccount, icrc_hash_created_at_time, icrc_hash_amount};
    int64_t types[6] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(&txn, (int64_t)tx->candid_rootType, fields, 6, types))
    CHECK_PARSER_ERR(candidExpectIcrcAccount(&txn, types[0]))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[1], Nat))
    CHECK_PARSER_ERR(candidExpectOptBlob(&txn, types[2]))
    CHECK_PARSER_ERR(candidExpectOptBlob(&txn, types[3]))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[4], Nat64))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[5], Nat))

    icrc_transfer_t *icrc = &ctx.tx_obj->tx_fields.call.data.icrcTransfer;

    // Read to (Account)
    CHECK_PARSER_ERR(readCandidIcrcAccount(&ctx, &icrc->account))

    // Read fee
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc->has_fee))
    if (icrc->has_fee) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc->fee))
    }

    // Read memo
    CHECK_PARSER_ERR(readCandidIcrcMemo(&ctx, &icrc->has_memo, &icrc->memo))

    // Read from_subaccount
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc->has_from_subaccount))
    if (icrc->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc->from_subaccount))
    }

    // Read has_created_at_time
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc->has_created_at_time))
    if (icrc->has_created_at_time) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc->created_at_time))
    }

    // Read amount
    CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc->amount))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return setIcpCanister(&ctx, &icrc->icp_canister);
}

parser_error_t readCandidICRC2Approve(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    zemu_log("readCandidICRC2Approve\n");

    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))

    // ApproveArgs = record {
    //   fee : opt nat; memo : opt blob; from_subaccount : opt Subaccount; created_at_time : opt nat64;
    //   amount : nat; expected_allowance : opt nat; expires_at : opt nat64; spender : Account }
    const uint64_t fields[] = {icrc_hash_fee,
                               icrc_hash_memo,
                               icrc_hash_from_subaccount,
                               icrc_hash_created_at_time,
                               icrc_hash_amount,
                               icrc_hash_expected_allowance,
                               icrc_hash_expires_at,
                               icrc_hash_spender};
    int64_t types[8] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(&txn, (int64_t)tx->candid_rootType, fields, 8, types))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[0], Nat))
    CHECK_PARSER_ERR(candidExpectOptBlob(&txn, types[1]))
    CHECK_PARSER_ERR(candidExpectOptBlob(&txn, types[2]))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[3], Nat64))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[4], Nat))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[5], Nat))
    CHECK_PARSER_ERR(candidExpectOptOf(&txn, types[6], Nat64))
    CHECK_PARSER_ERR(candidExpectIcrcAccount(&txn, types[7]))

    // Now extract the actual values into our structure - read in the same order as validation
    icrc2_approve_t *icrc2 = &ctx.tx_obj->tx_fields.call.data.icrc2_approve;

    // 1. Read fee
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc2->has_fee))
    if (icrc2->has_fee) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->fee))
    }

    // 2. Read memo
    CHECK_PARSER_ERR(readCandidIcrcMemo(&ctx, &icrc2->has_memo, &icrc2->memo))

    // 3. Read from_subaccount
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc2->has_from_subaccount))
    if (icrc2->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &icrc2->from_subaccount))
    }

    // 4. Read created_at_time
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc2->has_created_at_time))
    if (icrc2->has_created_at_time) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc2->created_at_time))
    }

    // 5. Read amount
    CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->amount))

    // 6. Read expected_allowance
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc2->has_expected_allowance))
    if (icrc2->has_expected_allowance) {
        CHECK_PARSER_ERR(readCandidLEB128(&ctx, &icrc2->expected_allowance))
    }

    // 7. Read expires_at
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &icrc2->has_expires_at))
    if (icrc2->has_expires_at) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &icrc2->expires_at))
    }

    // 8. Read spender (Account)
    CHECK_PARSER_ERR(readCandidIcrcAccount(&ctx, &icrc2->spender))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    CHECK_PARSER_ERR(setIcpCanister(&ctx, &icrc2->icp_canister))

    zemu_log("readCandidICRC2Approve OK\n");
    return parser_ok;
}

parser_error_t readCandidTransfer(parser_tx_t *tx, const uint8_t *input, uint16_t inputSize) {
    // Create context and auxiliary ctx
    CREATE_CTX(ctx, tx, input, inputSize)
    candid_transaction_t txn;
    txn.ctx.buffer = ctx.buffer;
    txn.ctx.bufferLen = ctx.bufferLen;
    txn.ctx.tx_obj = ctx.tx_obj;

    CHECK_PARSER_ERR(readCandidHeader(&ctx, &txn))
    CHECK_PARSER_ERR(readAndCheckRootType(&ctx))

    // TransferArgs = record {
    //   to : AccountIdentifier; fee : Tokens; memo : nat64;
    //   from_subaccount : opt SubAccount; created_at_time : opt TimeStamp; amount : Tokens }
    // AccountIdentifier = SubAccount = blob, Tokens = record { e8s : nat64 },
    // TimeStamp = record { timestamp_nanos : nat64 }
    const uint64_t fields[] = {transfer_hash_to,        transfer_hash_fee,
                               transfer_hash_memo,      transfer_hash_from_subaccount,
                               transfer_hash_timestamp, transfer_hash_amount};
    int64_t types[6] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(&txn, (int64_t)tx->candid_rootType, fields, 6, types))
    CHECK_PARSER_ERR(candidExpectBlob(&txn, types[0]))
    CHECK_PARSER_ERR(candidExpectRecordOf(&txn, types[1], transfer_hash_e8s, Nat64))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[2], Nat64))
    CHECK_PARSER_ERR(candidExpectOptBlob(&txn, types[3]))
    int64_t timestamp = 0;
    CHECK_PARSER_ERR(candidExpectOpt(&txn, types[4], &timestamp))
    CHECK_PARSER_ERR(candidExpectRecordOf(&txn, timestamp, transfer_hash_timestamp_nanos, Nat64))
    CHECK_PARSER_ERR(candidExpectRecordOf(&txn, types[5], transfer_hash_e8s, Nat64))

    // let's read!
    candid_transfer_t *transfer = &ctx.tx_obj->tx_fields.call.data.candid_transfer;

    // Read to (AccountIdentifier)
    uint8_t ownerSize = 0;
    CHECK_PARSER_ERR(readCandidByte(&ctx, &ownerSize))
    if (ownerSize != DFINITY_ADDR_LEN) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidBytes(&ctx, transfer->to, ownerSize))

    // Read fee (u64)
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->fee))

    // Read memo (u64)
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->memo))

    // Read from_subaccount (opt vec u8)
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &transfer->has_from_subaccount))
    if (transfer->has_from_subaccount) {
        CHECK_PARSER_ERR(readCandidText(&ctx, &transfer->from_subaccount))
        if (transfer->from_subaccount.len != DFINITY_SUBACCOUNT_LEN) {
            return parser_unexpected_value;
        }
    }

    // Read timestamp (opt u64)
    CHECK_PARSER_ERR(readCandidOptFlag(&ctx, &transfer->has_timestamp))
    if (transfer->has_timestamp) {
        CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->timestamp))
    }

    // Read amount
    CHECK_PARSER_ERR(readCandidNat64(&ctx, &transfer->amount))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
