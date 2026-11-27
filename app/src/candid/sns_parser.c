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
#include "sns_parser.h"

// Every wire type is checked against rs/sns/governance/canister/governance.did
// before the value it describes is read (see candid_helper.h): with anything
// looser, SNS governance and this parser can read different values from the
// same bytes.

__Z_INLINE parser_error_t readSNSCommandNeuronPermissions(parser_context_t *ctx, candid_transaction_t *txn, int64_t type,
                                                          uint64_t hash_permission_to) {
    // AddNeuronPermissions = record { permissions_to_add : opt NeuronPermissionList; principal_id : opt principal }
    // RemoveNeuronPermissions = record { permissions_to_remove : opt NeuronPermissionList; principal_id : opt principal }
    // NeuronPermissionList = record { permissions : vec int32 }
    const uint64_t fields[] = {hash_permission_to, sns_hash_principal_id};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))
    int64_t permissionList = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[0], &permissionList))
    int64_t permissions = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, permissionList, sns_hash_neuron_permission_list, &permissions))
    CHECK_PARSER_ERR(candidExpectVecOf(txn, permissions, Int32))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, types[1], Principal))

    // Read data
    sns_NeuronPermissions_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron.command.neuronPermissions;

    // Read Permissiones
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_permissionList))
    if (val->has_permissionList) {
        int32_t tmp_permission = 0;
        CHECK_PARSER_ERR(readCandidVecLength(ctx, &val->permissionList.list_size))

        val->permissionList.permissions_list_ptr = ctx->buffer + ctx->offset;
        for (uint8_t i = 0; i < val->permissionList.list_size; i++) {
            CHECK_PARSER_ERR(readCandidInt32(ctx, &tmp_permission))
            if (tmp_permission > NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION) {
                return parser_unexpected_value;
            }
        }
    }

    // Read Principal ID
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_principal))
    if (val->has_principal) {
        CHECK_PARSER_ERR(readCandidPrincipal(ctx, &val->principal))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readSNSCommandNeuronConfigure(parser_context_t *ctx, candid_transaction_t *txn, int64_t type) {
    sns_ManageNeuron_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron;

    // Configure = record { operation : opt Operation }
    int64_t operationField = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, sns_hash_operation, &operationField))
    int64_t operationType = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, operationField, &operationType))

    // Read Configure / Operation
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->command.configure.has_operation))
    if (!val->command.configure.has_operation) {
        return parser_unexpected_value;
    }
    candid_Operation_t *operation = &val->command.configure.operation;
    CHECK_PARSER_ERR(readCandidLEB128(ctx, &operation->which))  // read variant

    int64_t caseType = 0;
    CHECK_PARSER_ERR(candidVariantCase(txn, operationType, operation->which, &operation->hash, &caseType))

    switch (operation->hash) {
        case hash_operation_StartDissolving:
        case hash_operation_StopDissolving:
            // record {}
            CHECK_PARSER_ERR(candidExpectEmptyRecord(txn, caseType))
            break;
        case hash_operation_SetDissolvedTimestamp:
            // SetDissolveTimestamp = record { dissolve_timestamp_seconds : nat64 }
            CHECK_PARSER_ERR(candidExpectRecordOf(txn, caseType, hash_dissolve_timestamp_seconds, Nat64))

            // Read SetDissolvedTimestamp
            CHECK_PARSER_ERR(readCandidNat64(ctx, &operation->setDissolveTimestamp.dissolve_timestamp_seconds))

            if (operation->setDissolveTimestamp.dissolve_timestamp_seconds >= YEAR_2100_IN_SECONDS) {
                return parser_value_out_of_range;
            }
            break;

        default:
            ZEMU_LOGF(100, "Unimplemented operation | Hash: %llu\n", operation->hash)
            return parser_unexpected_value;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t readSNSCommandNeuronDisburse(parser_context_t *ctx, candid_transaction_t *txn, int64_t type) {
    // Disburse = record { to_account : opt Account; amount : opt Amount }
    // Account = record { owner : opt principal; subaccount : opt Subaccount }
    // Subaccount = record { subaccount : blob }
    // Amount = record { e8s : nat64 }
    const uint64_t fields[] = {sns_hash_disburse_to_account, sns_hash_opt_amount};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, type, fields, 2, types))

    int64_t account = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[0], &account))
    const uint64_t accountFields[] = {sns_hash_opt_principal, sns_hash_subaccount};
    int64_t accountTypes[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, account, accountFields, 2, accountTypes))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, accountTypes[0], Principal))
    int64_t subaccount = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, accountTypes[1], &subaccount))
    CHECK_PARSER_ERR(candidExpectRecordOfBlob(txn, subaccount, sns_hash_subaccount))

    int64_t amount = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &amount))
    CHECK_PARSER_ERR(candidExpectRecordOf(txn, amount, hash_e8s, Nat64))

    // Read data
    sns_Disburse_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron.command.sns_disburse;

    // Read Account
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_account))
    if (val->has_account) {
        CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->account.has_owner))
        if (val->account.has_owner) {
            CHECK_PARSER_ERR(readCandidPrincipal(ctx, &val->account.owner))
        }

        CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->account.has_subaccount))
        if (val->account.has_subaccount) {
            CHECK_PARSER_ERR(readCandidText(ctx, &val->account.subaccount))
        }
    }

    // Read Amount
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_amount))
    if (val->has_amount) {
        CHECK_PARSER_ERR(readCandidNat64(ctx, &val->amount))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t readSNSCommandStakeMaturity(parser_context_t *ctx, candid_transaction_t *txn, int64_t type) {
    // StakeMaturity = record { percentage_to_stake : opt nat32 }
    int64_t percentage = 0;
    CHECK_PARSER_ERR(candidExpectSingleFieldRecord(txn, type, hash_percentage_to_stake, &percentage))
    CHECK_PARSER_ERR(candidExpectOptOf(txn, percentage, Nat32))

    // Read data
    candid_StakeMaturity_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron.command.stake;
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_percentage_to_stake))
    if (val->has_percentage_to_stake) {
        CHECK_PARSER_ERR(readCandidNat32(ctx, &val->percentage_to_stake))
        // Sanity check
        if (val->percentage_to_stake == 0 || val->percentage_to_stake > 100) {
            return parser_value_out_of_range;
        }
    }

    return parser_ok;
}

parser_error_t readSNSManageNeuron(parser_context_t *ctx, candid_transaction_t *txn) {
    if (ctx == NULL || txn == NULL || txn->txn_length != 2) {
        return parser_unexpected_error;
    }

    // ManageNeuron = record { subaccount : blob; command : opt Command }
    // Only the variant case the value selects is decoded, so that is the one
    // checked below.
    const uint64_t fields[] = {sns_hash_subaccount, sns_hash_command};
    int64_t types[2] = {0};
    CHECK_PARSER_ERR(candidExpectRecord(txn, (int64_t)ctx->tx_obj->candid_rootType, fields, 2, types))
    CHECK_PARSER_ERR(candidExpectBlob(txn, types[0]))
    int64_t commandType = 0;
    CHECK_PARSER_ERR(candidExpectOpt(txn, types[1], &commandType))

    sns_ManageNeuron_t *val = &ctx->tx_obj->tx_fields.call.data.sns_manageNeuron;

    // Read subaccount
    CHECK_PARSER_ERR(readCandidText(ctx, &val->subaccount))

    // Read Command
    CHECK_PARSER_ERR(readCandidOptFlag(ctx, &val->has_command))
    if (val->has_command) {
        CHECK_PARSER_ERR(readCandidNat(ctx, &val->command.variant))
        int64_t caseType = 0;
        CHECK_PARSER_ERR(candidVariantCase(txn, commandType, val->command.variant, &val->command.hash, &caseType))

        switch (val->command.hash) {
            case sns_hash_command_AddNeuronPermissions: {
                CHECK_PARSER_ERR(readSNSCommandNeuronPermissions(ctx, txn, caseType, sns_hash_permissions_to_add))
                break;
            }
            case sns_hash_command_RemoveNeuronPermissions: {
                CHECK_PARSER_ERR(readSNSCommandNeuronPermissions(ctx, txn, caseType, sns_hash_permissions_to_remove))
                break;
            }
            case sns_hash_command_Configure: {
                CHECK_PARSER_ERR(readSNSCommandNeuronConfigure(ctx, txn, caseType))
                break;
            }
            case sns_hash_command_Disburse: {
                CHECK_PARSER_ERR(readSNSCommandNeuronDisburse(ctx, txn, caseType))
                break;
            }
            case sns_hash_command_StakeMaturity: {
                CHECK_PARSER_ERR(readSNSCommandStakeMaturity(ctx, txn, caseType))
                break;
            }

            default:
                ZEMU_LOGF(100, "Unimplemented command | Hash: %llu\n", val->command.hash)
                return parser_unexpected_type;
        }
    }

    if (ctx->bufferLen - ctx->offset > 0) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}
