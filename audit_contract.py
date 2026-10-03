import ctypes

SOVR_MAGIC = 0x534F5652
SOVA_MAGIC = 0x534F5641

SOVR_VERSION = 2
ROLE_FIDUCIARY_PR = 0xC001

MAX_NODES = 8
MAX_QUORUM_SIGNERS = 4
QUORUM_THRESHOLD = 3

# Status Codes
SOVR_STATUS_SUCCESS = 0x0000
SOVR_STATUS_ERR_MAGIC = 0xE001
SOVR_STATUS_REJECT_REPLAY = 0xE002
SOVR_STATUS_ERR_BOUNDS = 0xE003
SOVR_STATUS_ERR_QUORUM = 0xE004
SOVR_STATUS_ERR_UNAUTH = 0xE005

# Response Flags
SOVR_FLAG_STATUTORY_DUTY = 0x0001
SOVR_FLAG_CORP_DEFENSE_VALID = 0x0002
SOVR_FLAG_CAN_BE_ADMINISTERED = 0x0004
SOVR_FLAG_ANOMALY_DETECTED = 0x0008
SOVR_FLAG_QUORUM_VERIFIED = 0x0010

class SovereignWitness(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("signer_pubkey", ctypes.c_uint8 * 32),
        ("signature", ctypes.c_uint8 * 64)
    ]

class CLineageNode(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("era_year", ctypes.c_uint32),
        ("territorial_hub", ctypes.c_char * 24),
        ("title_type", ctypes.c_uint32)
    ]

class SovereignAuditFrame(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint16),
        ("fiduciary_role", ctypes.c_uint16),
        ("sequence_id", ctypes.c_uint64),
        ("veteran_verified", ctypes.c_uint8),
        ("statutory_duty", ctypes.c_uint8),
        ("corporate_defense_valid", ctypes.c_uint8),
        ("can_be_administered_away", ctypes.c_uint8),
        ("node_count", ctypes.c_uint32),
        ("claimant", ctypes.c_char * 64),
        ("dockets", (ctypes.c_char * 32) * 4),
        ("nodes", CLineageNode * MAX_NODES),
        ("computed_root_hash", ctypes.c_uint8 * 32),
        ("signer_bitmap", ctypes.c_uint8),
        ("quorum_count", ctypes.c_uint8),
        ("reserved_pad", ctypes.c_uint8 * 6),
        ("witnesses", SovereignWitness * MAX_QUORUM_SIGNERS)
    ]

class SovereignResponseFrame(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("status_code", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("root_hash", ctypes.c_uint8 * 32)
    ]

assert ctypes.sizeof(SovereignWitness) == 96, f"Witness size mismatch: {ctypes.sizeof(SovereignWitness)}"
assert ctypes.sizeof(CLineageNode) == 64, f"Node size mismatch: {ctypes.sizeof(CLineageNode)}"
assert ctypes.sizeof(SovereignAuditFrame) == 1152, f"Frame size mismatch: {ctypes.sizeof(SovereignAuditFrame)}"
assert ctypes.sizeof(SovereignResponseFrame) == 40, f"Response size mismatch: {ctypes.sizeof(SovereignResponseFrame)}"

import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from sovr_seq import get_next_seq

COMMITTEE_SEEDS = [
    b"\x11" * 32,  # Node U Esq
    b"\x22" * 32,  # Lineage Root
    b"\x33" * 32,  # Fed Trust
    b"\x44" * 32   # Corp Sentry
]
COMMITTEE_PRIVKEYS = [ed25519.Ed25519PrivateKey.from_private_bytes(seed) for seed in COMMITTEE_SEEDS]

def compute_frame_binary_hash(frame: SovereignAuditFrame) -> str:
    """Computes SHA-256 over exact memory buffers matching seL4 sovereign contract."""
    h = hashlib.sha256()
    base_addr = ctypes.addressof(frame)

    # 1. Raw 64-byte claimant buffer
    claimant_ptr = base_addr + SovereignAuditFrame.claimant.offset
    h.update(ctypes.string_at(claimant_ptr, 64))

    # 2. Raw 128-byte dockets buffer (4 * 32 bytes)
    dockets_ptr = base_addr + SovereignAuditFrame.dockets.offset
    h.update(ctypes.string_at(dockets_ptr, 4 * 32))

    # 3. Active nodes buffer (sizeof(CLineageNode) * node_count = 64 * node_count)
    nodes_ptr = base_addr + SovereignAuditFrame.nodes.offset
    node_bytes_len = ctypes.sizeof(CLineageNode) * frame.node_count
    h.update(ctypes.string_at(nodes_ptr, node_bytes_len))

    return h.hexdigest()

def serialize_estate_to_frame(seq_id=None, quorum_count=3, signer_bitmap=0x07) -> SovereignAuditFrame:
    """Serializes the sovereign estate state into a valid 1152-byte Quorum signed frame."""
    if seq_id is None:
        seq_id = get_next_seq(1)

    frame = SovereignAuditFrame()
    frame.magic = SOVR_MAGIC
    frame.version = SOVR_VERSION
    frame.fiduciary_role = ROLE_FIDUCIARY_PR
    frame.sequence_id = seq_id
    frame.veteran_verified = 1
    frame.statutory_duty = 1
    frame.corporate_defense_valid = 0
    frame.can_be_administered_away = 0
    frame.node_count = 1
    frame.claimant = b"Christopher Carroll"
    frame.dockets[0].value = b"4FA-23-01878PR-AK-SUPERIOR"[:31]

    frame.nodes[0].name = b"Dahzhit (Dehjalti')"[:31]
    frame.nodes[0].era_year = 1795
    frame.nodes[0].territorial_hub = b"Yukon / Porcupine"[:23]
    frame.nodes[0].title_type = 1

    frame.quorum_count = quorum_count
    frame.signer_bitmap = signer_bitmap

    # Message slice signed by quorum is exactly the first 320 bytes
    message_block = bytes(frame)[:320]

    witness_idx = 0
    for bit in range(4):
        if signer_bitmap & (1 << bit):
            if witness_idx < quorum_count:
                priv = COMMITTEE_PRIVKEYS[bit]
                pub_bytes = priv.public_key().public_bytes_raw()
                sig_bytes = priv.sign(message_block)

                for i in range(32):
                    frame.witnesses[witness_idx].signer_pubkey[i] = pub_bytes[i]
                for i in range(64):
                    frame.witnesses[witness_idx].signature[i] = sig_bytes[i]
                witness_idx += 1

    return frame
