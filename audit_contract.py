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
