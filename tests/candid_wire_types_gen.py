#!/usr/bin/env python3
"""Builds the "wire type ..." vectors in tests/candid_wire_types.json.

Each method gets well-typed base requests (the wire type real clients send,
exactly the canister's .did type) and variants that change one part of the wire
type or one flag byte. Every variant is a message the IC canisters either decode
to a different value than the device used to show (Candid subtyping: extra
fields skipped, missing opt fields null, an `opt T` with a non-matching `T`
decoded as null) or refuse outright; the device must refuse all of them.

Run: python3 -I tests/candid_wire_types_gen.py
Output: one line per vector: <name> <accept|refuse> <envelope hex>
The "client ..." vectors in the same file were captured from the client
libraries themselves (@dfinity/nns, sns, ledger-icp, ledger-icrc, Ledger Live,
Rust candid / dfx) and are not generated here.
"""

NULL, BOOL, NAT, INT = -1, -2, -3, -4
NAT8, NAT16, NAT32, NAT64 = -5, -6, -7, -8
INT8, INT16, INT32, INT64 = -9, -10, -11, -12
TEXT, RESERVED = -15, -16
PRINCIPAL = -24
OPT, VEC, RECORD, VARIANT = -18, -19, -20, -21


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def idl_hash(name):
    if isinstance(name, int):
        return name
    v = 0
    for c in name.encode():
        v = (v * 223 + c) % (1 << 32)
    return v


# ---- types ----
class Opt:
    def __init__(self, t):
        self.t = t


class Vec:
    def __init__(self, t):
        self.t = t


class Rec:
    def __init__(self, fields):
        self.fields = sorted(((idl_hash(n), t) for n, t in fields), key=lambda f: f[0])


class Var:
    def __init__(self, cases):
        self.cases = sorted(((idl_hash(n), t) for n, t in cases), key=lambda f: f[0])


BLOB = Vec(NAT8)


class Raw:
    """Value bytes written as they are."""

    def __init__(self, b):
        self.b = b


class Table:
    def __init__(self):
        self.entries = []
        self.keys = {}

    def ref(self, t):
        if isinstance(t, int):
            return t
        key = self.key(t)
        if key in self.keys:
            return self.keys[key]
        idx = len(self.entries)
        self.keys[key] = idx
        self.entries.append(None)
        if isinstance(t, Opt):
            body = sleb(OPT) + sleb(self.ref(t.t))
        elif isinstance(t, Vec):
            body = sleb(VEC) + sleb(self.ref(t.t))
        else:
            items = t.fields if isinstance(t, Rec) else t.cases
            body = sleb(RECORD if isinstance(t, Rec) else VARIANT) + leb(len(items))
            for h, ft in items:
                body += leb(h) + sleb(self.ref(ft))
        self.entries[idx] = body
        return idx

    def key(self, t):
        if isinstance(t, int):
            return t
        if isinstance(t, Opt):
            return ("opt", self.key(t.t))
        if isinstance(t, Vec):
            return ("vec", self.key(t.t))
        items = t.fields if isinstance(t, Rec) else t.cases
        return ("rec" if isinstance(t, Rec) else "var", tuple((h, self.key(ft)) for h, ft in items))


FIXED = {NAT8: 1, NAT16: 2, NAT32: 4, NAT64: 8, INT8: 1, INT16: 2, INT32: 4, INT64: 8}


def value(t, v):
    if isinstance(v, Raw):
        return v.b
    if isinstance(t, int):
        if t == NULL:
            return b""
        if t == BOOL:
            return bytes([1 if v else 0])
        if t == NAT:
            return leb(v)
        if t == INT:
            return sleb(v)
        if t in FIXED:
            return (v % (1 << (8 * FIXED[t]))).to_bytes(FIXED[t], "little")
        if t == TEXT:
            b = v.encode()
            return leb(len(b)) + b
        if t == PRINCIPAL:
            return b"\x01" + leb(len(v)) + v
        raise ValueError(t)
    if isinstance(t, Opt):
        return b"\x00" if v is None else b"\x01" + value(t.t, v)
    if isinstance(t, Vec):
        if isinstance(v, (bytes, bytearray)):
            v = list(v)
        return leb(len(v)) + b"".join(value(t.t, x) for x in v)
    if isinstance(t, Rec):
        vals = {idl_hash(k): x for k, x in v.items()}
        return b"".join(value(ft, vals[h]) for h, ft in t.fields)
    if isinstance(t, Var):
        name, x = v
        h = idl_hash(name)
        for i, (ch, ct) in enumerate(t.cases):
            if ch == h:
                return leb(i) + value(ct, x)
        raise KeyError(name)
    raise ValueError(t)


def didl(t, v):
    table = Table()
    root = table.ref(t)
    return b"DIDL" + leb(len(table.entries)) + b"".join(table.entries) + leb(1) + sleb(root) + value(t, v)


# ---- CBOR envelope ----
def cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cb_bytes(b):
    return cbor_head(2, len(b)) + b


def cb_text(s):
    s = s.encode()
    return cbor_head(3, len(s)) + s


def envelope(canister, method, arg, expiry=0x18666650643EA000):
    content = [
        ("arg", cb_bytes(arg)),
        ("canister_id", cb_bytes(canister)),
        ("ingress_expiry", cbor_head(0, expiry)),
        ("method_name", cb_text(method)),
        ("request_type", cb_text("call")),
        ("sender", cb_bytes(SENDER)),
    ]
    m = cbor_head(5, len(content)) + b"".join(cb_text(k) + v for k, v in content)
    return bytes.fromhex("d9d9f7") + cbor_head(5, 1) + cb_text("content") + m


ICP_LEDGER = bytes.fromhex("00000000000000020101")  # ryjl3-tyaaa-aaaaa-aaaba-cai
CKBTC_LEDGER = bytes.fromhex("0000000002300006" "0101")  # mxzaz-hqaaa-aaaar-qaada-cai
NNS_GOV = bytes.fromhex("00000000000000010101")  # rrkah-fqaaa-aaaaa-aaaaq-cai
SNS_GOV = bytes.fromhex("000000000200006d0101")  # an SNS governance canister id
SENDER = bytes.fromhex("841429ba30df507f14f52fbced0b037850b98d89aafaad5b7430f65802")
OWNER = bytes.fromhex("00000000014000f20101")
SUB = bytes(range(1, 33))
AID = bytes.fromhex("e07d1d48f3a8a5ab4ac0e2b5c9e1f2b3a4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9")
HOTKEY = bytes.fromhex("a1" * 28 + "02")


# ---- the .did types (as real clients encode them) ----
def account(owner_t=PRINCIPAL, sub_t=Opt(BLOB), extra=()):
    return Rec([("owner", owner_t), ("subaccount", sub_t), *extra])


def transfer_arg(**o):
    return Rec([
        ("to", o.get("to", account())),
        ("fee", o.get("fee", Opt(NAT))),
        ("memo", o.get("memo", Opt(BLOB))),
        ("from_subaccount", o.get("from_subaccount", Opt(BLOB))),
        ("created_at_time", o.get("created_at_time", Opt(NAT64))),
        ("amount", o.get("amount", NAT)),
    ] + list(o.get("extra", [])))


def approve_args(**o):
    return Rec([
        ("fee", o.get("fee", Opt(NAT))),
        ("memo", o.get("memo", Opt(BLOB))),
        ("from_subaccount", o.get("from_subaccount", Opt(BLOB))),
        ("created_at_time", o.get("created_at_time", Opt(NAT64))),
        ("amount", o.get("amount", NAT)),
        ("expected_allowance", o.get("expected_allowance", Opt(NAT))),
        ("expires_at", o.get("expires_at", Opt(NAT64))),
        ("spender", o.get("spender", account())),
    ])


TOKENS = Rec([("e8s", NAT64)])
TIMESTAMP = Rec([("timestamp_nanos", NAT64)])


def transfer_args(**o):
    return Rec([
        ("to", o.get("to", BLOB)),
        ("fee", o.get("fee", TOKENS)),
        ("memo", o.get("memo", NAT64)),
        ("from_subaccount", o.get("from_subaccount", Opt(BLOB))),
        ("created_at_time", o.get("created_at_time", Opt(TIMESTAMP))),
        ("amount", o.get("amount", TOKENS)),
    ])


NEURON_ID = Rec([("id", NAT64)])
AMOUNT = Rec([("e8s", NAT64)])
ACCOUNT_IDENTIFIER = Rec([("hash", BLOB)])
GOV_ACCOUNT = Rec([("owner", Opt(PRINCIPAL)), ("subaccount", Opt(BLOB))])


def nns_operation(**o):
    return Var([
        ("RemoveHotKey", o.get("RemoveHotKey", Rec([("hot_key_to_remove", Opt(PRINCIPAL))]))),
        ("AddHotKey", o.get("AddHotKey", Rec([("new_hot_key", Opt(PRINCIPAL))]))),
        ("ChangeAutoStakeMaturity", o.get("ChangeAutoStakeMaturity",
                                          Rec([("requested_setting_for_auto_stake_maturity", BOOL)]))),
        ("StopDissolving", Rec([])),
        ("StartDissolving", Rec([])),
        ("IncreaseDissolveDelay", o.get("IncreaseDissolveDelay",
                                        Rec([("additional_dissolve_delay_seconds", NAT32)]))),
        ("SetVisibility", o.get("SetVisibility", Rec([("visibility", Opt(INT32))]))),
        ("JoinCommunityFund", Rec([])),
        ("LeaveCommunityFund", Rec([])),
        ("SetDissolveTimestamp", o.get("SetDissolveTimestamp", Rec([("dissolve_timestamp_seconds", NAT64)]))),
    ])


def nns_command(**o):
    return Var([
        ("Spawn", o.get("Spawn", Rec([("percentage_to_spawn", Opt(NAT32)), ("new_controller", Opt(PRINCIPAL)),
                                      ("nonce", Opt(NAT64))]))),
        ("Split", o.get("Split", Rec([("amount_e8s", NAT64)]))),
        ("Follow", o.get("Follow", Rec([("topic", INT32), ("followees", Vec(NEURON_ID))]))),
        ("Configure", Rec([("operation", Opt(o.get("Operation", nns_operation())))])),
        ("RegisterVote", o.get("RegisterVote", Rec([("vote", INT32), ("proposal", Opt(NEURON_ID))]))),
        ("Merge", o.get("Merge", Rec([("source_neuron_id", Opt(NEURON_ID))]))),
        ("StakeMaturity", o.get("StakeMaturity", Rec([("percentage_to_stake", Opt(NAT32))]))),
        ("Disburse", o.get("Disburse", Rec([("to_account", Opt(ACCOUNT_IDENTIFIER)), ("amount", Opt(AMOUNT))]))),
        ("RefreshVotingPower", o.get("RefreshVotingPower", Rec([]))),
        ("DisburseMaturity", o.get("DisburseMaturity", Rec([
            ("percentage_to_disburse", NAT32),
            ("to_account", Opt(GOV_ACCOUNT)),
            ("to_account_identifier", Opt(ACCOUNT_IDENTIFIER)),
        ]))),
    ])


def manage_neuron(**o):
    return Rec([
        ("id", o.get("id", Opt(NEURON_ID))),
        ("command", Opt(o.get("command", nns_command()))),
        ("neuron_id_or_subaccount", o.get("selector", Opt(Var([("Subaccount", BLOB), ("NeuronId", NEURON_ID)])))),
    ])


def mn(command, neuron=123456789):
    return {"id": {"id": neuron}, "command": command, "neuron_id_or_subaccount": None}


SNS_ACCOUNT = Rec([("owner", Opt(PRINCIPAL)), ("subaccount", Opt(Rec([("subaccount", BLOB)])))])
PERMISSION_LIST = Rec([("permissions", Vec(INT32))])


def sns_command(**o):
    return Var([
        ("Configure", Rec([("operation", Opt(Var([
            ("StopDissolving", Rec([])),
            ("StartDissolving", Rec([])),
            ("SetDissolveTimestamp", o.get("SetDissolveTimestamp", Rec([("dissolve_timestamp_seconds", NAT64)]))),
        ])))])),
        ("StakeMaturity", o.get("StakeMaturity", Rec([("percentage_to_stake", Opt(NAT32))]))),
        ("RemoveNeuronPermissions", o.get("RemoveNeuronPermissions", Rec([
            ("permissions_to_remove", Opt(PERMISSION_LIST)), ("principal_id", Opt(PRINCIPAL))]))),
        ("AddNeuronPermissions", o.get("AddNeuronPermissions", Rec([
            ("permissions_to_add", Opt(o.get("PermissionList", PERMISSION_LIST))),
            ("principal_id", o.get("principal_id", Opt(PRINCIPAL)))]))),
        ("Disburse", o.get("Disburse", Rec([("to_account", Opt(o.get("Account", SNS_ACCOUNT))),
                                            ("amount", Opt(o.get("Amount", AMOUNT)))]))),
    ])


def sns_manage_neuron(**o):
    return Rec([("subaccount", o.get("subaccount", BLOB)), ("command", Opt(o.get("command", sns_command())))])


def list_neurons(**o):
    return Rec([
        ("neuron_ids", o.get("neuron_ids", Vec(NAT64))),
        ("include_neurons_readable_by_caller", BOOL),
        ("include_empty_neurons_readable_by_caller", Opt(BOOL)),
    ])


def update_node_provider(**o):
    return Rec([("reward_account", Opt(o.get("AccountIdentifier", ACCOUNT_IDENTIFIER)))])


VECTORS = []


def add(name, expect, canister, method, t, v):
    VECTORS.append((name, expect, envelope(canister, method, didl(t, v))))


def gen():
    # ---------------- icrc1_transfer ----------------
    def tv(**o):
        v = {"to": {"owner": OWNER, "subaccount": SUB}, "fee": 10_000, "memo": (65800).to_bytes(8, "big"),
             "from_subaccount": SUB, "created_at_time": 1_700_000_000_000_000_000, "amount": 100_000_000}
        v.update(o)
        return v

    m = "icrc1_transfer"
    add("icrc1_transfer base", "accept", CKBTC_LEDGER, m, transfer_arg(), tv())
    add("icrc1_transfer base all null", "accept", CKBTC_LEDGER, m, transfer_arg(),
        tv(to={"owner": OWNER, "subaccount": None}, fee=None, memo=None, from_subaccount=None, created_at_time=None))
    add("icrc1_transfer to.subaccount opt vec nat", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=account(sub_t=Opt(Vec(NAT)))), tv())
    add("icrc1_transfer to.subaccount opt vec int8", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=account(sub_t=Opt(Vec(INT8)))), tv())
    add("icrc1_transfer to.subaccount opt text", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=account(sub_t=Opt(TEXT))), tv(to={"owner": OWNER, "subaccount": "x" * 32}))
    add("icrc1_transfer to with an extra field", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=account(extra=[("a", Opt(NAT))])), tv(to={"owner": OWNER, "subaccount": SUB, "a": None}))
    add("icrc1_transfer to.owner renamed", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=Rec([("owner_", PRINCIPAL), ("subaccount", Opt(BLOB))])),
        tv(to={"owner_": OWNER, "subaccount": SUB}))
    add("icrc1_transfer to.owner opt principal", "refuse", CKBTC_LEDGER, m,
        transfer_arg(to=account(owner_t=Opt(PRINCIPAL))), tv(to={"owner": OWNER, "subaccount": None}))
    add("icrc1_transfer memo opt vec int8", "refuse", CKBTC_LEDGER, m, transfer_arg(memo=Opt(Vec(INT8))), tv())
    add("icrc1_transfer memo opt vec null", "refuse", CKBTC_LEDGER, m, transfer_arg(memo=Opt(Vec(NULL))),
        tv(memo=[None] * 3))
    add("icrc1_transfer from_subaccount opt vec nat16", "refuse", CKBTC_LEDGER, m,
        transfer_arg(from_subaccount=Opt(Vec(NAT16))), tv(from_subaccount=[1] * 16))
    add("icrc1_transfer fee opt int", "refuse", CKBTC_LEDGER, m, transfer_arg(fee=Opt(INT)), tv())
    add("icrc1_transfer created_at_time opt int64", "refuse", CKBTC_LEDGER, m,
        transfer_arg(created_at_time=Opt(INT64)), tv())
    add("icrc1_transfer amount int", "refuse", CKBTC_LEDGER, m, transfer_arg(amount=INT), tv())
    add("icrc1_transfer amount nat64", "refuse", CKBTC_LEDGER, m, transfer_arg(amount=NAT64), tv())
    add("icrc1_transfer created_at_time renamed", "refuse", CKBTC_LEDGER, m,
        Rec([("to", account()), ("fee", Opt(NAT)), ("memo", Opt(BLOB)), ("from_subaccount", Opt(BLOB)),
             ("created_at_timf", Opt(NAT64)), ("amount", NAT)]),
        {"to": {"owner": OWNER, "subaccount": SUB}, "fee": 10_000, "memo": None, "from_subaccount": None,
         "created_at_timf": 5, "amount": 100_000_000})
    add("icrc1_transfer opt flag 2", "refuse", CKBTC_LEDGER, m, transfer_arg(), tv(from_subaccount=Raw(b"\x02")))
    add("icrc1_transfer principal tag 0", "refuse", CKBTC_LEDGER, m, transfer_arg(),
        tv(to={"owner": Raw(b"\x00"), "subaccount": None}))

    # ---------------- icrc2_approve ----------------
    def av(**o):
        v = {"fee": 10_000, "memo": (7).to_bytes(8, "big"), "from_subaccount": SUB,
             "created_at_time": 1_700_000_000_000_000_000, "amount": 100_000_000, "expected_allowance": 5,
             "expires_at": 1_800_000_000_000_000_000, "spender": {"owner": OWNER, "subaccount": SUB}}
        v.update(o)
        return v

    m = "icrc2_approve"
    add("icrc2_approve base", "accept", ICP_LEDGER, m, approve_args(), av())
    add("icrc2_approve base all null", "accept", ICP_LEDGER, m, approve_args(),
        av(fee=None, memo=None, from_subaccount=None, created_at_time=None, expected_allowance=None,
           expires_at=None, spender={"owner": OWNER, "subaccount": None}))
    add("icrc2_approve spender { a : blob; owner : principal }", "refuse", ICP_LEDGER, m,
        approve_args(spender=Rec([("a", BLOB), ("owner", PRINCIPAL)])),
        av(spender={"a": SUB, "owner": HOTKEY}))
    add("icrc2_approve spender.subaccount opt vec int8", "refuse", ICP_LEDGER, m,
        approve_args(spender=account(sub_t=Opt(Vec(INT8)))), av())
    add("icrc2_approve spender with an extra field", "refuse", ICP_LEDGER, m,
        approve_args(spender=account(extra=[("z", Opt(NAT))])), av(spender={"owner": OWNER, "subaccount": SUB,
                                                                            "z": None}))
    add("icrc2_approve expected_allowance opt int", "refuse", ICP_LEDGER, m,
        approve_args(expected_allowance=Opt(INT)), av())
    add("icrc2_approve expires_at opt int64", "refuse", ICP_LEDGER, m, approve_args(expires_at=Opt(INT64)), av())
    add("icrc2_approve memo opt vec nat", "refuse", ICP_LEDGER, m, approve_args(memo=Opt(Vec(NAT))), av())
    add("icrc2_approve opt flag 2", "refuse", ICP_LEDGER, m, approve_args(), av(expected_allowance=Raw(b"\x02")))

    # ---------------- legacy transfer ----------------
    def lv(**o):
        v = {"to": AID, "fee": {"e8s": 10_000}, "memo": 0, "from_subaccount": SUB,
             "created_at_time": {"timestamp_nanos": 1_700_000_000_000_000_000}, "amount": {"e8s": 100_000_000}}
        v.update(o)
        return v

    m = "transfer"
    add("transfer base", "accept", ICP_LEDGER, m, transfer_args(), lv())
    add("transfer base all null", "accept", ICP_LEDGER, m, transfer_args(),
        lv(from_subaccount=None, created_at_time=None))
    add("transfer amount { a; e8s; pad }", "refuse", ICP_LEDGER, m,
        transfer_args(amount=Rec([("a", NAT64), ("e8s", NAT64), ("pad", BLOB)])),
        lv(amount={"a": 0, "e8s": 5_000_000_000, "pad": bytes(8)}))
    add("transfer amount renamed field", "refuse", ICP_LEDGER, m, transfer_args(amount=Rec([("e9s", NAT64)])),
        lv(amount={"e9s": 100_000_000}))
    add("transfer amount { e8s : int64 }", "refuse", ICP_LEDGER, m, transfer_args(amount=Rec([("e8s", INT64)])),
        lv())
    add("transfer fee with an extra field", "refuse", ICP_LEDGER, m,
        transfer_args(fee=Rec([("e8s", NAT64), ("z", Opt(NAT))])), lv(fee={"e8s": 10_000, "z": None}))
    add("transfer from_subaccount opt vec null", "refuse", ICP_LEDGER, m,
        transfer_args(from_subaccount=Opt(Vec(NULL))), lv(from_subaccount=[None] * 32))
    add("transfer from_subaccount opt vec int8", "refuse", ICP_LEDGER, m,
        transfer_args(from_subaccount=Opt(Vec(INT8))), lv())
    add("transfer created_at_time opt nat64", "refuse", ICP_LEDGER, m, transfer_args(created_at_time=Opt(NAT64)),
        lv(created_at_time=1_700_000_000_000_000_000))
    add("transfer created_at_time renamed field", "refuse", ICP_LEDGER, m,
        transfer_args(created_at_time=Opt(Rec([("timestamp", NAT64)]))), lv(created_at_time={"timestamp": 1}))
    add("transfer to vec int8", "refuse", ICP_LEDGER, m, transfer_args(to=Vec(INT8)), lv())
    add("transfer memo int64", "refuse", ICP_LEDGER, m, transfer_args(memo=INT64), lv())
    add("transfer opt flag 2", "refuse", ICP_LEDGER, m, transfer_args(), lv(created_at_time=Raw(b"\x02")))

    # ---------------- NNS manage_neuron ----------------
    m = "manage_neuron"
    t = manage_neuron()
    nns = [
        ("Split", {"amount_e8s": 100_000_000}),
        ("Merge", {"source_neuron_id": {"id": 42}}),
        ("Spawn", {"percentage_to_spawn": 50, "new_controller": HOTKEY, "nonce": 7}),
        ("StakeMaturity", {"percentage_to_stake": 25}),
        ("Disburse", {"to_account": {"hash": AID}, "amount": {"e8s": 100_000_000}}),
        ("RegisterVote", {"vote": 1, "proposal": {"id": 1234}}),
        ("Follow", {"topic": 4, "followees": [{"id": 1}, {"id": 2}]}),
        ("RefreshVotingPower", {}),
        ("DisburseMaturity", {"percentage_to_disburse": 100, "to_account": {"owner": HOTKEY, "subaccount": SUB},
                              "to_account_identifier": None}),
        ("Configure", {"operation": ("IncreaseDissolveDelay", {"additional_dissolve_delay_seconds": 86400})}),
        ("Configure", {"operation": ("SetDissolveTimestamp", {"dissolve_timestamp_seconds": 1_900_000_000})}),
        ("Configure", {"operation": ("AddHotKey", {"new_hot_key": HOTKEY})}),
        ("Configure", {"operation": ("RemoveHotKey", {"hot_key_to_remove": HOTKEY})}),
        ("Configure", {"operation": ("ChangeAutoStakeMaturity", {"requested_setting_for_auto_stake_maturity": True})}),
        ("Configure", {"operation": ("SetVisibility", {"visibility": 2})}),
        ("Configure", {"operation": ("StartDissolving", {})}),
    ]
    for name, v in nns:
        label = name if name != "Configure" else "Configure " + v["operation"][0]
        add(f"manage_neuron {label} base", "accept", NNS_GOV, m, t, mn((name, v)))
    add("manage_neuron by NeuronId selector base", "accept", NNS_GOV, m, t,
        {"id": None, "command": ("Split", {"amount_e8s": 100_000_000}),
         "neuron_id_or_subaccount": ("NeuronId", {"id": 123456789})})
    add("manage_neuron Disburse to_account and amount null base", "accept", NNS_GOV, m, t,
        mn(("Disburse", {"to_account": None, "amount": None})))
    add("manage_neuron DisburseMaturity to account identifier base", "accept", NNS_GOV, m, t,
        mn(("DisburseMaturity", {"percentage_to_disburse": 50, "to_account": None,
                                 "to_account_identifier": {"hash": AID}})))

    def nv(command, **o):
        return manage_neuron(command=nns_command(**o)), mn(command)

    for name, (tt, v) in {
        "Disburse amount { a : nat64 }": nv(("Disburse", {"to_account": {"hash": AID}, "amount": {"a": 1}}),
                                            Disburse=Rec([("to_account", Opt(ACCOUNT_IDENTIFIER)),
                                                          ("amount", Opt(Rec([("a", NAT64)])))])),
        "Disburse amount { e8s : int64 }": nv(("Disburse", {"to_account": None, "amount": {"e8s": 1}}),
                                              Disburse=Rec([("to_account", Opt(ACCOUNT_IDENTIFIER)),
                                                            ("amount", Opt(Rec([("e8s", INT64)])))])),
        "Disburse to_account { hash : vec int8 }": nv(
            ("Disburse", {"to_account": {"hash": AID}, "amount": None}),
            Disburse=Rec([("to_account", Opt(Rec([("hash", Vec(INT8))]))), ("amount", Opt(AMOUNT))])),
        "Disburse to_account blob": nv(("Disburse", {"to_account": AID, "amount": None}),
                                       Disburse=Rec([("to_account", Opt(BLOB)), ("amount", Opt(AMOUNT))])),
        "Disburse with an extra field": nv(
            ("Disburse", {"to_account": None, "amount": None, "z": None}),
            Disburse=Rec([("to_account", Opt(ACCOUNT_IDENTIFIER)), ("amount", Opt(AMOUNT)), ("z", Opt(NAT))])),
        "DisburseMaturity to_account { a : blob; owner : opt principal }": nv(
            ("DisburseMaturity", {"percentage_to_disburse": 100, "to_account": {"a": SUB, "owner": HOTKEY},
                                  "to_account_identifier": None}),
            DisburseMaturity=Rec([("percentage_to_disburse", NAT32),
                                  ("to_account", Opt(Rec([("a", BLOB), ("owner", Opt(PRINCIPAL))]))),
                                  ("to_account_identifier", Opt(ACCOUNT_IDENTIFIER))])),
        "DisburseMaturity to_account.subaccount opt vec int8": nv(
            ("DisburseMaturity", {"percentage_to_disburse": 100, "to_account": {"owner": HOTKEY, "subaccount": SUB},
                                  "to_account_identifier": None}),
            DisburseMaturity=Rec([("percentage_to_disburse", NAT32),
                                  ("to_account", Opt(Rec([("owner", Opt(PRINCIPAL)),
                                                          ("subaccount", Opt(Vec(INT8)))]))),
                                  ("to_account_identifier", Opt(ACCOUNT_IDENTIFIER))])),
        "DisburseMaturity to_account.owner principal": nv(
            ("DisburseMaturity", {"percentage_to_disburse": 100, "to_account": {"owner": HOTKEY, "subaccount": None},
                                  "to_account_identifier": None}),
            DisburseMaturity=Rec([("percentage_to_disburse", NAT32),
                                  ("to_account", Opt(Rec([("owner", PRINCIPAL), ("subaccount", Opt(BLOB))]))),
                                  ("to_account_identifier", Opt(ACCOUNT_IDENTIFIER))])),
        "DisburseMaturity to_account_identifier opt null with a value": nv(
            ("DisburseMaturity", {"percentage_to_disburse": 100, "to_account": None,
                                  "to_account_identifier": Raw(b"\x01")}),
            DisburseMaturity=Rec([("percentage_to_disburse", NAT32), ("to_account", Opt(GOV_ACCOUNT)),
                                  ("to_account_identifier", Opt(NULL))])),
        "Split { amount_e8s : int64 }": nv(("Split", {"amount_e8s": 1}), Split=Rec([("amount_e8s", INT64)])),
        "Split with an extra field": nv(("Split", {"amount_e8s": 1, "z": None}),
                                        Split=Rec([("amount_e8s", NAT64), ("z", Opt(NAT))])),
        "Merge source { id : int64 }": nv(("Merge", {"source_neuron_id": {"id": 1}}),
                                          Merge=Rec([("source_neuron_id", Opt(Rec([("id", INT64)])))])),
        "Spawn new_controller opt text": nv(
            ("Spawn", {"percentage_to_spawn": None, "new_controller": "x", "nonce": None}),
            Spawn=Rec([("percentage_to_spawn", Opt(NAT32)), ("new_controller", Opt(TEXT)), ("nonce", Opt(NAT64))])),
        "Spawn percentage opt int32": nv(
            ("Spawn", {"percentage_to_spawn": 50, "new_controller": None, "nonce": None}),
            Spawn=Rec([("percentage_to_spawn", Opt(INT32)), ("new_controller", Opt(PRINCIPAL)),
                       ("nonce", Opt(NAT64))])),
        "StakeMaturity opt int32": nv(("StakeMaturity", {"percentage_to_stake": 25}),
                                      StakeMaturity=Rec([("percentage_to_stake", Opt(INT32))])),
        "RegisterVote proposal { id : int64 }": nv(
            ("RegisterVote", {"vote": 1, "proposal": {"id": 1}}),
            RegisterVote=Rec([("vote", INT32), ("proposal", Opt(Rec([("id", INT64)])))])),
        "RegisterVote vote nat32": nv(("RegisterVote", {"vote": 1, "proposal": {"id": 1}}),
                                      RegisterVote=Rec([("vote", NAT32), ("proposal", Opt(NEURON_ID))])),
        "Follow followees vec nat64": nv(("Follow", {"topic": 4, "followees": [1, 2]}),
                                         Follow=Rec([("topic", INT32), ("followees", Vec(NAT64))])),
        "Follow followees vec { id : int64 }": nv(
            ("Follow", {"topic": 4, "followees": [{"id": 1}]}),
            Follow=Rec([("topic", INT32), ("followees", Vec(Rec([("id", INT64)])))])),
        "RefreshVotingPower with a field": nv(("RefreshVotingPower", {"z": None}),
                                              RefreshVotingPower=Rec([("z", Opt(NAT))])),
        "SetVisibility opt nat32": nv(("Configure", {"operation": ("SetVisibility", {"visibility": 2})}),
                                      Operation=nns_operation(SetVisibility=Rec([("visibility", Opt(NAT32))]))),
        "AddHotKey with the RemoveHotKey field": nv(
            ("Configure", {"operation": ("AddHotKey", {"hot_key_to_remove": HOTKEY})}),
            Operation=nns_operation(AddHotKey=Rec([("hot_key_to_remove", Opt(PRINCIPAL))]))),
        "AddHotKey opt text": nv(("Configure", {"operation": ("AddHotKey", {"new_hot_key": "x"})}),
                                 Operation=nns_operation(AddHotKey=Rec([("new_hot_key", Opt(TEXT))]))),
        "IncreaseDissolveDelay int32": nv(
            ("Configure", {"operation": ("IncreaseDissolveDelay", {"additional_dissolve_delay_seconds": 1})}),
            Operation=nns_operation(IncreaseDissolveDelay=Rec([("additional_dissolve_delay_seconds", INT32)]))),
        "SetDissolveTimestamp int64": nv(
            ("Configure", {"operation": ("SetDissolveTimestamp", {"dissolve_timestamp_seconds": 1})}),
            Operation=nns_operation(SetDissolveTimestamp=Rec([("dissolve_timestamp_seconds", INT64)]))),
        "ChangeAutoStakeMaturity opt bool": nv(
            ("Configure", {"operation": ("ChangeAutoStakeMaturity",
                                         {"requested_setting_for_auto_stake_maturity": True})}),
            Operation=nns_operation(ChangeAutoStakeMaturity=Rec([("requested_setting_for_auto_stake_maturity",
                                                                  Opt(BOOL))]))),
    }.items():
        add(f"manage_neuron {name}", "refuse", NNS_GOV, m, tt, v)

    add("manage_neuron id { id : int64 }", "refuse", NNS_GOV, m, manage_neuron(id=Opt(Rec([("id", INT64)]))),
        mn(("Split", {"amount_e8s": 1})))
    add("manage_neuron id with an extra field", "refuse", NNS_GOV, m,
        manage_neuron(id=Opt(Rec([("id", NAT64), ("z", Opt(NAT))]))),
        {"id": {"id": 1, "z": None}, "command": ("Split", {"amount_e8s": 1}), "neuron_id_or_subaccount": None})
    add("manage_neuron NeuronId selector { id : int64 }", "refuse", NNS_GOV, m,
        manage_neuron(selector=Opt(Var([("Subaccount", BLOB), ("NeuronId", Rec([("id", INT64)]))]))),
        {"id": None, "command": ("Split", {"amount_e8s": 1}), "neuron_id_or_subaccount": ("NeuronId", {"id": 1})})
    add("manage_neuron Subaccount selector vec int8", "refuse", NNS_GOV, m,
        manage_neuron(selector=Opt(Var([("Subaccount", Vec(INT8)), ("NeuronId", NEURON_ID)]))),
        {"id": None, "command": ("Split", {"amount_e8s": 1}), "neuron_id_or_subaccount": ("Subaccount", SUB)})
    add("manage_neuron opt flag 2", "refuse", NNS_GOV, m, t,
        {"id": Raw(b"\x02" + (1).to_bytes(8, "little")), "command": ("Split", {"amount_e8s": 1}),
         "neuron_id_or_subaccount": None})
    add("manage_neuron ChangeAutoStakeMaturity bool 2", "refuse", NNS_GOV, m, t,
        mn(("Configure", {"operation": ("ChangeAutoStakeMaturity",
                                        {"requested_setting_for_auto_stake_maturity": Raw(b"\x02")})})))
    add("manage_neuron Spawn principal tag 0", "refuse", NNS_GOV, m, t,
        mn(("Spawn", {"percentage_to_spawn": None, "new_controller": Raw(b"\x01\x00"), "nonce": None})))

    # ---------------- SNS manage_neuron ----------------
    t = sns_manage_neuron()

    def sv(command):
        return {"subaccount": SUB, "command": command}

    sns = [
        ("AddNeuronPermissions", {"permissions_to_add": {"permissions": [3, 4, 9]}, "principal_id": HOTKEY}),
        ("RemoveNeuronPermissions", {"permissions_to_remove": {"permissions": [4]}, "principal_id": HOTKEY}),
        ("Disburse", {"to_account": {"owner": HOTKEY, "subaccount": {"subaccount": SUB}},
                      "amount": {"e8s": 100_000_000}}),
        ("StakeMaturity", {"percentage_to_stake": 25}),
        ("Configure", {"operation": ("SetDissolveTimestamp", {"dissolve_timestamp_seconds": 1_900_000_000})}),
        ("Configure", {"operation": ("StopDissolving", {})}),
    ]
    for name, v in sns:
        label = name if name != "Configure" else "Configure " + v["operation"][0]
        add(f"sns manage_neuron {label} base", "accept", SNS_GOV, m, t, sv((name, v)))
    add("sns manage_neuron Disburse to_account and amount null base", "accept", SNS_GOV, m, t,
        sv(("Disburse", {"to_account": None, "amount": None})))

    perm = ("AddNeuronPermissions", {"permissions_to_add": {"permissions": [3, 4]}, "principal_id": HOTKEY})
    disb = ("Disburse", {"to_account": {"owner": HOTKEY, "subaccount": {"subaccount": SUB}},
                         "amount": {"e8s": 100_000_000}})
    for name, (tt, v) in {
        "permissions vec nat32": (sns_manage_neuron(command=sns_command(
            PermissionList=Rec([("permissions", Vec(NAT32))]))), sv(perm)),
        "permissions vec int8": (sns_manage_neuron(command=sns_command(
            PermissionList=Rec([("permissions", Vec(INT8))]))), sv(perm)),
        "permission list with an extra field": (sns_manage_neuron(command=sns_command(
            PermissionList=Rec([("permissions", Vec(INT32)), ("z", Opt(NAT))]))),
            sv(("AddNeuronPermissions", {"permissions_to_add": {"permissions": [3], "z": None},
                                         "principal_id": HOTKEY}))),
        "principal_id opt text": (sns_manage_neuron(command=sns_command(principal_id=Opt(TEXT))),
                                  sv(("AddNeuronPermissions", {"permissions_to_add": {"permissions": [3]},
                                                               "principal_id": "x"}))),
        "Disburse subaccount { subaccount : vec int8 }": (sns_manage_neuron(command=sns_command(
            Account=Rec([("owner", Opt(PRINCIPAL)), ("subaccount", Opt(Rec([("subaccount", Vec(INT8))])))]))),
            sv(disb)),
        "Disburse subaccount blob": (sns_manage_neuron(command=sns_command(
            Account=Rec([("owner", Opt(PRINCIPAL)), ("subaccount", Opt(BLOB))]))),
            sv(("Disburse", {"to_account": {"owner": HOTKEY, "subaccount": SUB}, "amount": None}))),
        "Disburse account { a : blob; owner : opt principal }": (sns_manage_neuron(command=sns_command(
            Account=Rec([("a", BLOB), ("owner", Opt(PRINCIPAL))]))),
            sv(("Disburse", {"to_account": {"a": SUB, "owner": HOTKEY}, "amount": None}))),
        "Disburse amount { e8s : int64 }": (sns_manage_neuron(command=sns_command(
            Amount=Rec([("e8s", INT64)]))), sv(disb)),
        "Disburse amount { a : nat64 }": (sns_manage_neuron(command=sns_command(
            Amount=Rec([("a", NAT64)]))),
            sv(("Disburse", {"to_account": None, "amount": {"a": 1}}))),
        "StakeMaturity opt int32": (sns_manage_neuron(command=sns_command(
            StakeMaturity=Rec([("percentage_to_stake", Opt(INT32))]))),
            sv(("StakeMaturity", {"percentage_to_stake": 25}))),
        "SetDissolveTimestamp int64": (sns_manage_neuron(command=sns_command(
            SetDissolveTimestamp=Rec([("dissolve_timestamp_seconds", INT64)]))),
            sv(("Configure", {"operation": ("SetDissolveTimestamp", {"dissolve_timestamp_seconds": 1})}))),
        "subaccount vec int8": (sns_manage_neuron(subaccount=Vec(INT8)), sv(perm)),
        "opt flag 2": (t, sv(("StakeMaturity", {"percentage_to_stake": Raw(b"\x02" + (25).to_bytes(4, "little"))}))),
        "principal tag 0": (t, sv(("AddNeuronPermissions", {"permissions_to_add": None,
                                                            "principal_id": Raw(b"\x01\x00")}))),
    }.items():
        add(f"sns manage_neuron {name}", "refuse", SNS_GOV, m, tt, v)

    # ---------------- list_neurons ----------------
    m = "list_neurons"
    lnv = {"neuron_ids": [1, 2], "include_neurons_readable_by_caller": True,
           "include_empty_neurons_readable_by_caller": None}
    add("list_neurons base", "accept", NNS_GOV, m, list_neurons(), lnv)
    add("list_neurons neuron_ids vec int64", "refuse", NNS_GOV, m, list_neurons(neuron_ids=Vec(INT64)), lnv)
    add("list_neurons neuron_ids vec nat8", "refuse", NNS_GOV, m, list_neurons(neuron_ids=Vec(NAT8)), lnv)
    add("list_neurons bool 2", "refuse", NNS_GOV, m, list_neurons(),
        dict(lnv, include_neurons_readable_by_caller=Raw(b"\x02")))
    add("list_neurons opt flag 2", "refuse", NNS_GOV, m, list_neurons(),
        dict(lnv, include_empty_neurons_readable_by_caller=Raw(b"\x02")))

    # ---------------- update_node_provider ----------------
    m = "update_node_provider"
    add("update_node_provider base", "accept", NNS_GOV, m, update_node_provider(), {"reward_account": {"hash": AID}})
    add("update_node_provider hash vec int8", "refuse", NNS_GOV, m,
        update_node_provider(AccountIdentifier=Rec([("hash", Vec(INT8))])), {"reward_account": {"hash": AID}})
    add("update_node_provider account identifier with an extra field", "refuse", NNS_GOV, m,
        update_node_provider(AccountIdentifier=Rec([("hash", BLOB), ("z", Opt(NAT))])),
        {"reward_account": {"hash": AID, "z": None}})
    add("update_node_provider opt flag 2", "refuse", NNS_GOV, m, update_node_provider(),
        {"reward_account": Raw(b"\x02" + leb(32) + AID)})


if __name__ == "__main__":
    gen()
    for name, expect, env in VECTORS:
        print(f"{name.replace(' ', '_')} {expect} {env.hex()}")
