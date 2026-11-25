import ctypes as C
from pathlib import Path

HOME = Path.home()
FIXTURE = Path("/tmp/longfellow-dob-cli-test")
RUST = HOME / "multipaz-dob/multipaz-longfellow/rust"

LIB = RUST / "target/debug/libzkp.so"
ARCHIVE = HOME / "longfellow-dob-only-export/circuits.zst"

DOB_ID = (
    "b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926"
)

class Attribute(C.Structure):
    _fields_ = [
        ("namespace_id", C.c_uint8 * 64),
        ("id", C.c_uint8 * 32),
        ("cbor_value", C.c_uint8 * 64),
        ("namespace_len", C.c_size_t),
        ("id_len", C.c_size_t),
        ("cbor_value_len", C.c_size_t),
    ]

class Spec(C.Structure):
    _fields_ = [
        ("system", C.c_char_p),
        ("circuit_hash", C.c_char * 65),
        ("num_attributes", C.c_size_t),
        ("version", C.c_size_t),
        ("block_enc_hash", C.c_size_t),
        ("block_enc_sig", C.c_size_t),
    ]

def attribute(dob):
    a = Attribute()
    ns = b"org.iso.18013.5.1"
    name = b"birth_date"
    value = b"\xd9\x03\xec\x6a" + dob.encode("ascii")

    assert len(value) == 14

    a.namespace_id[:len(ns)] = ns
    a.id[:len(name)] = name
    a.cbor_value[:len(value)] = value
    a.namespace_len = len(ns)
    a.id_len = len(name)
    a.cbor_value_len = len(value)
    return a

def buffer(data):
    return C.create_string_buffer(data, len(data))

def ptr(obj):
    return C.cast(obj, C.c_void_p)

metadata = (FIXTURE / "metadata.txt").read_text().splitlines()
assert len(metadata) == 4, f"Expected four metadata lines: {metadata}"

pkx, pky, doc_type, now = [x.encode() for x in metadata]

mdoc_data = (FIXTURE / "mdoc.bin").read_bytes()
transcript_data = (FIXTURE / "transcript.bin").read_bytes()
archive_data = ARCHIVE.read_bytes()
existing_proof = (FIXTURE / "proof.bin").read_bytes()

mdoc = buffer(mdoc_data)
transcript = buffer(transcript_data)
circuits = buffer(archive_data)

spec = Spec()
spec.system = b"longfellow-libzk-v1"
spec.circuit_hash = DOB_ID.encode()
spec.num_attributes = 1
spec.version = 8
spec.block_enc_hash = 5264
spec.block_enc_sig = 4445

lib = C.CDLL(str(LIB))

P = C.c_void_p
S = C.c_size_t
STR = C.c_char_p
ATTR = C.POINTER(Attribute)
SPEC = C.POINTER(Spec)

lib.run_mdoc_prover_dob.argtypes = [
    P, S, P, S, STR, STR, P, S, ATTR, S, STR,
    C.POINTER(P), C.POINTER(S), STR, SPEC, STR, STR,
]
lib.run_mdoc_prover_dob.restype = C.c_int

lib.run_mdoc_verifier_dob.argtypes = [
    P, S, STR, STR, P, S, ATTR, S, STR,
    P, S, STR, SPEC, STR, STR,
]
lib.run_mdoc_verifier_dob.restype = C.c_int

lib.free_mdoc_proof.argtypes = [P, S]
lib.free_mdoc_proof.restype = None

lower = b"1960-01-01"
upper = b"1980-12-31"

def verify(proof_bytes, cutoff, earliest):
    proof_buffer = buffer(proof_bytes)

    # The actual DOB is not supplied to the verifier.
    attr = attribute("1999-01-01")

    return lib.run_mdoc_verifier_dob(
        ptr(circuits),
        len(archive_data),
        pkx,
        pky,
        ptr(transcript),
        len(transcript_data),
        C.byref(attr),
        1,
        now,
        ptr(proof_buffer),
        len(proof_bytes),
        doc_type,
        C.byref(spec),
        cutoff,
        earliest,
    )

print("1. Verifying existing CLI proof through Multipaz...")
rc = verify(existing_proof, lower, upper)
print("   Result:", rc)
assert rc == 0, f"Existing proof verification failed: {rc}"

print("2. Generating a new proof through Multipaz...")

prover_attr = attribute("1971-09-01")
proof_ptr = P()
proof_len = S()

rc = lib.run_mdoc_prover_dob(
    ptr(circuits),
    len(archive_data),
    ptr(mdoc),
    len(mdoc_data),
    pkx,
    pky,
    ptr(transcript),
    len(transcript_data),
    C.byref(prover_attr),
    1,
    now,
    C.byref(proof_ptr),
    C.byref(proof_len),
    doc_type,
    C.byref(spec),
    lower,
    upper,
)

print("   Result:", rc)
assert rc == 0, f"DOB prover failed: {rc}"
assert proof_ptr.value and proof_len.value > 0

try:
    new_proof = C.string_at(proof_ptr, proof_len.value)
finally:
    lib.free_mdoc_proof(proof_ptr, proof_len)

print("   Proof size:", len(new_proof), "bytes")

print("3. Verifying new Multipaz proof...")
rc = verify(new_proof, lower, upper)
print("   Result:", rc)
assert rc == 0, f"New proof verification failed: {rc}"

print("4. Testing an incorrect DOB interval...")
rc = verify(new_proof, b"2000-01-01", b"2010-12-31")
print("   Result:", rc)
assert rc != 0, "Incorrect interval was accepted!"

print("5. Testing an incorrect circuit ID...")
wrong_spec = Spec()
C.memmove(C.byref(wrong_spec), C.byref(spec), C.sizeof(Spec))
wrong_spec.circuit_hash = b"0" * 64

attr = attribute("1999-01-01")
proof_buffer = buffer(new_proof)

rc = lib.run_mdoc_verifier_dob(
    ptr(circuits),
    len(archive_data),
    pkx,
    pky,
    ptr(transcript),
    len(transcript_data),
    C.byref(attr),
    1,
    now,
    ptr(proof_buffer),
    len(new_proof),
    doc_type,
    C.byref(wrong_spec),
    lower,
    upper,
)

print("   Result:", rc)
assert rc != 0, "Incorrect circuit ID was accepted!"

(FIXTURE / "multipaz-proof.bin").write_bytes(new_proof)

print()
print("ALL MULTIPAZ DOB NATIVE TESTS PASSED")
print("Circuit ID:", DOB_ID)
