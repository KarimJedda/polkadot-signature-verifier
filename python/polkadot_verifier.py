from ctypes import CDLL, c_char_p, c_uint8
from pathlib import Path

# Load the shared library
lib_path = Path(__file__).parent.parent / "target/release/libpolkadot_sig_verifier.so"
lib = CDLL(str(lib_path))

# Configure function signatures
lib.verify_polkadot_signature.argtypes = [c_char_p, c_char_p, c_char_p]
lib.verify_polkadot_signature.restype = c_uint8
lib.get_version.argtypes = []
lib.get_version.restype = c_char_p


def verify(address: str, signature: str, message: str) -> bool:
    """Verify a Polkadot SR25519 signature.

    Automatically wraps message in <Bytes>...</Bytes> as per Polkadot signing format.
    """
    wrapped_message = f"<Bytes>{message}</Bytes>"
    result = lib.verify_polkadot_signature(
        address.encode(),
        signature.encode(),
        wrapped_message.encode(),
    )
    return result == 1


def get_version() -> str:
    """Get library version."""
    return lib.get_version().decode()
