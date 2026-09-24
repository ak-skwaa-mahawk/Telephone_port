import ctypes
import hashlib
from jump_chain import estate, TitleStatus, AuthorityLevel

# C-compatible struct definitions (GCC System V ABI packed layout)
class CLineageNode(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("era_year", ctypes.c_uint16),
        ("territorial_hub", ctypes.c_char * 30),
        ("title_type", ctypes.c_uint32),
    ]

class SovereignAuditFrame(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),                     # 0x534F5652 ("SOVR")
        ("version", ctypes.c_uint16),                   # 0x0001
        ("fiduciary_role", ctypes.c_uint16),            # 0xC001
        ("sequence_id", ctypes.c_uint64),               # Sequence 27 Monotonic Anti-Replay Counter
        ("veteran_verified", ctypes.c_uint8),
        ("node_count", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 6),
        ("claimant", ctypes.c_char * 64),
        ("dockets", (ctypes.c_char * 48) * 3),
        ("nodes", CLineageNode * 8),
        ("computed_root_hash", ctypes.c_uint8 * 32),
        ("statutory_duty", ctypes.c_uint32),
        ("corporate_defense_valid", ctypes.c_uint8),
        ("can_be_administered_away", ctypes.c_uint8),
        ("status_padding", ctypes.c_uint8 * 2),
    ]

def serialize_estate_to_frame() -> SovereignAuditFrame:
    frame = SovereignAuditFrame()
    frame.magic = 0x534F5652
    frame.version = 1
    frame.fiduciary_role = 0xC001 if estate.fiduciary_role == AuthorityLevel.FIDUCIARY_PR else 0x0000
    frame.veteran_verified = 1 if estate.veteran_verified else 0
    frame.node_count = len(estate.lineage_graph)
    frame.claimant = estate.claimant.encode("utf-8")

    for idx, docket in enumerate(estate.court_probate_dockets[:3]):
        raw_docket = docket.encode("utf-8")[:47]
        frame.dockets[idx].value = raw_docket

    for idx, node in enumerate(estate.lineage_graph[:8]):
        frame.nodes[idx].name = node.name.encode("utf-8")[:31]
        frame.nodes[idx].era_year = node.era_year
        frame.nodes[idx].territorial_hub = node.territorial_hub.encode("utf-8")[:29]
        frame.nodes[idx].title_type = 1 if node.title_type == TitleStatus.ABORIGINAL_SOVEREIGN else 2

    return frame

def compute_frame_binary_hash(frame: SovereignAuditFrame) -> str:
    """Computes SHA-256 over exact memory buffers matching seL4 main.c."""
    h = hashlib.sha256()
    base_addr = ctypes.addressof(frame)

    # 1. Raw 64-byte claimant buffer (sizeof(frame.claimant))
    claimant_ptr = base_addr + SovereignAuditFrame.claimant.offset
    h.update(ctypes.string_at(claimant_ptr, 64))

    # 2. Raw 144-byte dockets buffer (sizeof(frame.dockets))
    dockets_ptr = base_addr + SovereignAuditFrame.dockets.offset
    h.update(ctypes.string_at(dockets_ptr, 3 * 48))

    # 3. Active nodes buffer (sizeof(CLineageNode) * node_count = 68 * node_count)
    nodes_ptr = base_addr + SovereignAuditFrame.nodes.offset
    node_bytes_len = ctypes.sizeof(CLineageNode) * frame.node_count
    h.update(ctypes.string_at(nodes_ptr, node_bytes_len))

    return h.hexdigest()

if __name__ == "__main__":
    frame = serialize_estate_to_frame()
    raw_bytes = bytes(frame)
    binary_hash = compute_frame_binary_hash(frame)

    print(f"[+] SovereignAuditFrame packed successfully ({len(raw_bytes)} bytes).")
    print(f"[+] Python Binary SHA-256 Digest:")
    print(f"    {binary_hash}")

    with open("audit_frame.bin", "wb") as f:
        f.write(raw_bytes)
    print(f"[+] Saved audit_frame.bin")

# ============================================================================
# Structured Response Frame (40 bytes) Matching seL4 sovereign_contract.h
# ============================================================================
SOVA_MAGIC = 0x534F5641

SOVR_STATUS_SUCCESS    = 0x0000
SOVR_STATUS_ERR_UNAUTH = 0xE001
SOVR_STATUS_ERR_MAGIC  = 0xE002
SOVR_STATUS_ERR_BOUNDS = 0xE003

SOVR_FLAG_STATUTORY_DUTY      = (1 << 0)
SOVR_FLAG_CORP_DEFENSE_VALID  = (1 << 1)
SOVR_FLAG_CAN_BE_ADMINISTERED = (1 << 2)

class SovereignResponseFrame(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("status_code", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("root_hash", ctypes.c_uint8 * 32),
    ]

assert ctypes.sizeof(SovereignResponseFrame) == 40, f"Expected 40 bytes, got {ctypes.sizeof(SovereignResponseFrame)}"
