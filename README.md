# Polkadot Signature Verifier

FFI library for verifying Polkadot SR25519 signatures. 

Disclaimer: Not audited / verified, use at your own risk. 

## Build

```bash
cargo build --release
```

## Usage

### Ruby

```ruby
require_relative 'ruby/polkadot_verifier'

is_valid = PolkadotSignatureVerifier.verify(
  address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  signature: "0x...",
  message: "my_challenge_token"  # raw message, <Bytes> wrapping handled automatically
)
```

### Python

```python
from python.polkadot_verifier import verify

is_valid = verify(
    address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    signature="0x...",
    message="my_challenge_token",  # raw message, <Bytes> wrapping handled automatically
)
```

