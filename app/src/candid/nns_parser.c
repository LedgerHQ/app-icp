/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
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
#include "nns_parser.h"

// Every wire type is checked against rs/nns/governance/canister/governance.did
// before the value it describes is read (see candid_helper.h): with anything
// looser, governance and this parser can read different values from the same
// bytes.

// NeuronId = ProposalId = record { id : nat64 }
__Z_INLINE parser_error_t candidExpectNeuronId(candid_transaction_t *txn, int64_t type) {
    return candidExpectRecordOf(txn, type, hash_id, Nat64);
}

// opt AccountIdentifier, AccountIdentifier = record { hash : blob }
// `nullable`: also accept `opt null`, whose value can only be null (*isNull is set).
__Z_INLINE parser_error_t candidExpectOptAccountIdentifier(candid_transaction_t *txn, int64_t type, bool nullable,
                                                           bool *isNull) {
    int64_t accountIdentifier = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, type, &accountIdentifier))
    *isNull = nullable && accountIdentifier == Null;
    if (*isNull) {
        return parser_ok;
    }
    return candidExpectRecordOfBlob(txn, accountIdentifier, hash_hash);
}

__Z_INLINE parser_error_t readCommandSplit(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                           candid_ManageNeuron_t *val) {
    // Split = record { amount_e8s : nat64 }
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, type, hash_amount_e8s, Nat64))

    // Read Split
    CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.split.amount_e8s))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandMerge(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                           candid_ManageNeuron_t *val) {
    // Merge = record { source_neuron_id : opt NeuronId }
    int64_t source = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, hash_source_neuron_id, &source))
    int64_t neuronId = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, source, &neuronId))
    CHECK_PARSER_ERR(candidExpectNeuronId(txn, neuronId))

    // Read Merge
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.merge.has_source))
    if (!val->command.merge.has_source) {
        // https://github.com/Zondax/ledger-icp/issues/149
        // indicates that missing source should be rejected
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.merge.source.id))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandSpawn(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                           candid_ManageNeuron_t *val) {
    // Spawn = record { percentage_to_spawn : opt nat32; new_controller : opt principal; nonce : opt nat64 }
    const uint64_t fields[] = {hash_percentage_to_spawn, hash_new_controller, hash_nonce};
    int64_t types[3] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 3, types))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, types[0], Nat32))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, types[1], Principal))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, types[2], Nat64))

    // now let's read
    // Percentage to spawn
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.spawn.has_percentage_to_spawn))
    if (val->command.spawn.has_percentage_to_spawn) {
        CHECK_PARSER_ERR(readCandidNat32(ctx, &val->command.spawn.percentage_to_spawn))
        // Sanity check
        if (val->command.spawn.percentage_to_spawn == 0 || val->command.spawn.percentage_to_spawn > 100) {
            return parser_value_out_of_range;
        }
    }

    // Controller
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.spawn.has_controller))
    if (val->command.spawn.has_controller) {
        CHECK_PARSER_ERR(readCandidPrincipal(ctx, &val->command.spawn.new_controller))
    }

    // Nonce
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.spawn.has_nonce))
    if (val->command.spawn.has_nonce) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.spawn.nonce))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandStakeMaturity(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                   candid_ManageNeuron_t *val) {
    // StakeMaturity = record { percentage_to_stake : opt nat32 }
    int64_t percentage = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, hash_percentage_to_stake, &percentage))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, percentage, Nat32))

    // now let's read
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.stake.has_percentage_to_stake))
    if (val->command.stake.has_percentage_to_stake) {
        CHECK_PARSER_ERR(readCandidNat32(ctx, &val->command.stake.percentage_to_stake))
        // Sanity check
        if (val->command.stake.percentage_to_stake == 0 || val->command.stake.percentage_to_stake > 100) {
            return parser_value_out_of_range;
        }
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandDisburse(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                              candid_ManageNeuron_t *val) {
    // Disburse = record { to_account : opt AccountIdentifier; amount : opt Amount }
    // Amount = record { e8s : nat64 }
    const uint64_t fields[] = {hash_field_disburse_account, hash_opt_amount};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))
    bool unused = false;
    CHECK_PARSER_ERR(candidExpectOptAccountIdentifier(txn, types[0], false, &unused))
    int64_t amount = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &amount))
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, amount, hash_e8s, Nat64))

    // now let's read
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.disburse.has_account_identifier))
    if (val->command.disburse.has_account_identifier) {
        CHECK_PARSER_ERR(readCandidText(ctx, &val->command.disburse.account_identifier))
    }
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.disburse.has_amount))
    if (val->command.disburse.has_amount) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.disburse.amount))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandRegisterVote(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                  candid_ManageNeuron_t *val) {
    // RegisterVote = record { vote : int32; proposal : opt ProposalId }
    const uint64_t fields[] = {hash_field_vote, hash_field_proposal};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[0], Int32))
    int64_t proposal = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &proposal))
    CHECK_PARSER_ERR(candidExpectNeuronId(txn, proposal))

    // now let's read
    CHECK_PARSER_ERR(readCandidInt32(ctx, &val->command.vote.vote))
    if (val->command.vote.vote != 1 && val->command.vote.vote != 2) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.vote.has_proposal))
    if (!val->command.vote.has_proposal) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidNat64(ctx, &val->command.vote.proposal.id))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandFollow(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                            candid_ManageNeuron_t *val) {
    // Follow = record { topic : int32; followees : vec NeuronId }
    const uint64_t fields[] = {hash_field_follow_topic, hash_field_follow_followees};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))
    CHECK_PARSER_ERR(candidExpectPrimitive(types[0], Int32))
    int64_t followee = 0;
    CHECK_PARSER_ERR(candidExpectVec(txn, types[1], &followee))
    CHECK_PARSER_ERR(candidExpectNeuronId(txn, followee))

    // now let's read
    CHECK_PARSER_ERR(readCandidInt32(ctx, &val->command.follow.topic))
    if (val->command.follow.topic < 0 || val->command.follow.topic > FOLLOW_TOPIC_SNS_AND_NEURONS_FUND) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidVecLength(ctx, &val->command.follow.followees_size))
    val->command.follow.followees_ptr = ctx->buffer + ctx->offset;
    uint64_t tmp_followee = 0;
    for (uint8_t i = 0; i < val->command.follow.followees_size; i++) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &tmp_followee))
    }

    return parser_ok;
}

// RefreshVotingPower = record {}
// https://github.com/dfinity/ic/blob/master/rs/nns/governance/canister/governance.did
__Z_INLINE parser_error_t readCommandRefreshVotingPower(__Z_UNUSED parser_context_t *ctx, candid_transaction_t *txn,
                                                        int64_t type, __Z_UNUSED candid_ManageNeuron_t *val) {
    return candidExpectEmptyRecord(txn, type);
}

__Z_INLINE parser_error_t readCommandDisburseMaturity(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                      candid_ManageNeuron_t *val) {
    // DisburseMaturity = record {
    //   to_account_identifier : opt AccountIdentifier;
    //   to_account : opt Account;
    //   percentage_to_disburse : nat32 }
    // Account = record { owner : opt principal; subaccount : opt blob }
    // Fields are sorted by hash, which is the order above.
    const uint64_t fields[] = {hash_to_account_identifier, hash_field_disburse_account, hash_percentage_to_disburse};
    int64_t types[3] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 3, types))

    // Both destinations may also come as `opt null`, which can only hold null.
    bool accountIdentifierIsNull = false;
    CHECK_PARSER_ERR(candidExpectOptAccountIdentifier(txn, types[0], true, &accountIdentifierIsNull))

    int64_t account = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &account))
    const bool accountIsNull = account == Null;
    if (!accountIsNull) {
        const uint64_t accountFields[] = {icrc_hash_owner, icrc_hash_subaccount};
        int64_t accountTypes[2] = {0};
        CHECK_PARSER_ERR(candidExpectRecord(txn, account, accountFields, 2, accountTypes))
        CHECK_PARSER_ERR(candidExpectOptOf(txn, accountTypes[0], Principal))
        CHECK_PARSER_ERR(candidExpectOptBlob(txn, accountTypes[1]))
    }

    CHECK_PARSER_ERR(candidExpectPrimitive(types[2], Nat32))

    // Now let's read
    candid_DisburseMaturity_t *disburseMaturity = &val->command.disburseMaturity;

    // Field 0 data: to_account_identifier (opt AccountIdentifier)
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &disburseMaturity->has_to_account_identifier))
    if (disburseMaturity->has_to_account_identifier) {
        if (accountIdentifierIsNull) {
            return parser_unexpected_type;
        }
        CHECK_PARSER_ERR(readCandidText(ctx, &disburseMaturity->to_account_identifier))
    }

    // Field 1 data: to_account (opt Account)
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &disburseMaturity->has_to_account))
    disburseMaturity->to_account.has_owner = 0;
    disburseMaturity->to_account.has_subaccount = 0;
    if (disburseMaturity->has_to_account) {
        if (accountIsNull) {
            return parser_unexpected_type;
        }
        // Read Account.owner (optional Principal)
        CHECK_PARSER_ERR(readCandidOptFlag(ctx, &disburseMaturity->to_account.has_owner))
        if (disburseMaturity->to_account.has_owner) {
            CHECK_PARSER_ERR(readCandidPrincipal(ctx, &disburseMaturity->to_account.owner))
        }

        // Read Account.subaccount (optional)
        CHECK_PARSER_ERR(readCandidOptFlag(ctx, &disburseMaturity->to_account.has_subaccount))
        if (disburseMaturity->to_account.has_subaccount) {
            CHECK_PARSER_ERR(readCandidText(ctx, &disburseMaturity->to_account.subaccount))
        }
    }

    // Field 2 data: percentage_to_disburse (Nat32)
    CHECK_PARSER_ERR(readCandidNat32(ctx, &disburseMaturity->percentage_to_disburse))

    // Sanity check percentage
    if (disburseMaturity->percentage_to_disburse == 0 || disburseMaturity->percentage_to_disburse > 100) {
        return parser_value_out_of_range;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationSetVisibility(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                     candid_Operation_t *operation) {
    // SetVisibility = record { visibility : opt int32 }
    int64_t visibility = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, hash_field_visibility, &visibility))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, visibility, Int32))

    uint8_t has_visibility = 0;
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &has_visibility))
    if (!has_visibility) {
        // Visibility must be present in this transaction
        return parser_unexpected_value;
    }

    int32_t value = 0;
    CHECK_PARSER_ERR(readCandidInt32(ctx, &value))
    // visibility allowed at the time implementing this:
    // [1, 2]
    if (value < 1 || value > 2) {
        return parser_invalid_visibility;
    }

    operation->set_visibility.visibility = value;
    operation->set_visibility.has_visibility = 1;

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationSetDissolveTimestamp(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                            candid_Operation_t *operation) {
    // SetDissolveTimestamp = record { dissolve_timestamp_seconds : nat64 }
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, type, hash_dissolve_timestamp_seconds, Nat64))

    // Read SetDissolvedTimestamp
    CHECK_PARSER_ERR(readCandidNat64(ctx, &operation->setDissolveTimestamp.dissolve_timestamp_seconds))

    if (operation->setDissolveTimestamp.dissolve_timestamp_seconds >= YEAR_2100_IN_SECONDS) {
        return parser_value_out_of_range;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationChangeAutoStakeMaturity(parser_context_t *ctx, candid_transaction_t *txn,
                                                               int64_t type, candid_Operation_t *operation) {
    // ChangeAutoStakeMaturity = record { requested_setting_for_auto_stake_maturity : bool }
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, type, hash_setting_auto_stake_maturity, Bool))

    // let's read
    CHECK_PARSER_ERR(readCandidBool(ctx, &operation->autoStakeMaturity.requested_setting_for_auto_stake_maturity))

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationIncreaseDissolveDelay(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                             candid_Operation_t *operation) {
    // IncreaseDissolveDelay = record { additional_dissolve_delay_seconds : nat32 }
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, type, hash_setting_increse_dissolve_delay, Nat32))

    // let's read
    CHECK_PARSER_ERR(readCandidNat32(ctx, &operation->increaseDissolveDelay.dissolve_timestamp_seconds))

    return parser_ok;
}

__Z_INLINE parser_error_t readOperationAddRemoveHotkey(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                       candid_Operation_t *operation) {
    // AddHotKey = record { new_hot_key : opt principal }
    // RemoveHotKey = record { hot_key_to_remove : opt principal }
    const uint64_t field = operation->hash == hash_operation_AddHotkey ? hash_setting_addhotkey : hash_setting_remove_hotkey;
    int64_t hotkey = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, field, &hotkey))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, hotkey, Principal))

    // let's read
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &operation->hotkey.has_principal))
    if (!operation->hotkey.has_principal) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(readCandidPrincipal(ctx, &operation->hotkey.principal))

    return parser_ok;
}

__Z_INLINE parser_error_t readCommandConfigure(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                               candid_ManageNeuron_t *val) {
    // Configure = record { operation : opt Operation }
    int64_t operationField = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, hash_operation, &operationField))
    int64_t operationType = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, operationField, &operationType))

    // Read Configure / Operation
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.configure.has_operation))
    if (!val->command.configure.has_operation) {
        return parser_unexpected_value;
    }
    candid_Operation_t *operation = &val->command.configure.operation;
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &operation->which))

    int64_t caseType = 0;
    CHECK_PARSER_ERR(candidVariantCase(txn, operationType, operation->which, &operation->hash, &caseType))

    switch (operation->hash) {
        case hash_operation_SetDissolvedTimestamp:
            CHECK_PARSER_ERR(readOperationSetDissolveTimestamp(ctx, txn, caseType, operation))
            break;
        case hash_operation_ChangeAutoStakeMaturity:
            CHECK_PARSER_ERR(readOperationChangeAutoStakeMaturity(ctx, txn, caseType, operation))
            break;
        case hash_operation_IncreaseDissolveDelay:
            CHECK_PARSER_ERR(readOperationIncreaseDissolveDelay(ctx, txn, caseType, operation))
            break;
        case hash_operation_AddHotkey:
        case hash_operation_RemoveHotkey:
            CHECK_PARSER_ERR(readOperationAddRemoveHotkey(ctx, txn, caseType, operation))
            break;
        case hash_operation_LeaveNeuronsFund:
        case hash_operation_StartDissolving:
        case hash_operation_StopDissolving:
        case hash_operation_JoinNeuronsFund:
            // record {}
            CHECK_PARSER_ERR(candidExpectEmptyRecord(txn, caseType))
            break;
        case hash_operation_SetVisibility:
            CHECK_PARSER_ERR(readOperationSetVisibility(ctx, txn, caseType, operation))
            break;

        default:
            ZEMU_LOGF(50, "Unknown operation hash: 0x%08X%08X\n", (uint32_t)(operation->hash >> 32),
                      (uint32_t)(operation->hash & 0xFFFFFFFF));
            return parser_unexpected_value;
    }
    return parser_ok;
}

parser_error_t readNNSManageNeuron(parser_context_t *ctx, candid_transaction_t *txn) {
    if (ctx == NULL || txn == NULL || txn->txn_length != 3) {
        return parser_unexpected_error;
    }

    candid_ManageNeuron_t *val = &ctx->tx_obj->tx_fields.call.data.candid_manageNeuron;

    // ManageNeuron = record {
    //   id : opt NeuronId;
    //   command : opt Command;
    //   neuron_id_or_subaccount : opt NeuronIdOrSubaccount }
    // Only the variant case a value selects is decoded, so that is the one
    // checked below; governance decodes the others from no bytes at all.
    const uint64_t fields[] = {hash_id, hash_command, hash_neuron_id_or_subaccount};
    int64_t types[3] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, (int64_t)ctx->tx_obj->candid_rootType, fields, 3, types))
    int64_t neuronId = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[0], &neuronId))
    CHECK_PARSER_ERR(candidExpectNeuronId(txn, neuronId))
    int64_t commandType = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &commandType))
    int64_t selectorType = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[2], &selectorType))

    // Read Id
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_id))
    if (val->has_id) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->id.id))
    }

    // Read Command
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_command))
    if (val->has_command) {
        CHECK_PARSER_ERR(readCandidNat(ctx, &val->command.variant))
        int64_t caseType = 0;
        CHECK_PARSER_ERR(candidVariantCase(txn, commandType, val->command.variant, &val->command.hash, &caseType))

        switch (val->command.hash) {
            case hash_command_Split: {
                CHECK_PARSER_ERR(readCommandSplit(ctx, txn, caseType, val))
                break;
            }

            case hash_command_Merge: {
                CHECK_PARSER_ERR(readCommandMerge(ctx, txn, caseType, val))
                break;
            }

            case hash_command_Configure: {
                CHECK_PARSER_ERR(readCommandConfigure(ctx, txn, caseType, val))
                break;
            }
            case hash_command_Spawn: {
                CHECK_PARSER_ERR(readCommandSpawn(ctx, txn, caseType, val))
                break;
            }
            case hash_command_StakeMaturity:
                CHECK_PARSER_ERR(readCommandStakeMaturity(ctx, txn, caseType, val))
                break;

            case hash_command_Disburse:
                CHECK_PARSER_ERR(readCommandDisburse(ctx, txn, caseType, val))
                break;

            case hash_command_RegisterVote:
                CHECK_PARSER_ERR(readCommandRegisterVote(ctx, txn, caseType, val))
                break;

            case hash_command_Follow:
                CHECK_PARSER_ERR(readCommandFollow(ctx, txn, caseType, val))
                break;
            case hash_command_RefreshVotingPower:
                CHECK_PARSER_ERR(readCommandRefreshVotingPower(ctx, txn, caseType, val))
                break;
            case hash_command_DisburseMaturity:
                CHECK_PARSER_ERR(readCommandDisburseMaturity(ctx, txn, caseType, val))
                break;

            default:
                return parser_unexpected_type;
        }
    }

    // Read neuron id or subaccount
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_neuron_id_or_subaccount))
    if (val->has_neuron_id_or_subaccount) {
        uint64_t index = 0;
        CHECK_PARSER_ERR(readCandidLEB128(ctx, &index))

        uint64_t neuron_id_or_subaccount_hash = 0;
        int64_t caseType = 0;
        CHECK_PARSER_ERR(candidVariantCase(txn, selectorType, index, &neuron_id_or_subaccount_hash, &caseType))

        // NeuronIdOrSubaccount = variant { Subaccount : blob; NeuronId : NeuronId }
        // `which` names the case, 0 Subaccount and 1 NeuronId (their positions in
        // the full variant), whatever position it has in this wire type.
        switch (neuron_id_or_subaccount_hash) {
            case hash_subaccount: {
                CHECK_PARSER_ERR(candidExpectBlob(txn, caseType))
                val->neuron_id_or_subaccount.which = 0;

                // Read subaccount
                CHECK_PARSER_ERR(readCandidText(ctx, &val->neuron_id_or_subaccount.subaccount))
                break;
            }
            case hash_neuron_id: {
                CHECK_PARSER_ERR(candidExpectNeuronId(txn, caseType))
                val->neuron_id_or_subaccount.which = 1;

                // Read neuron id
                CHECK_PARSER_ERR(readCandidNat64(ctx, &val->neuron_id_or_subaccount.neuronId.id))
                break;
            }
            default:
                return parser_value_out_of_range;
        }
    }

    if (ctx->bufferLen - ctx->offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
