use sp_core::{
  crypto::Ss58Codec,
  sr25519::{Public, Signature},
  Pair,
};
use std::ffi::{CStr, c_char};

/// Verify a Polkadot SR25519 signature
/// 
/// # Arguments
/// * `address_ptr` - SS58-encoded Polkadot address (e.g., "14zNh...")
/// * `signature_ptr` - Hex-encoded signature (with or without 0x prefix)
/// * `message_ptr` - The original message that was signed
/// 
/// # Returns
/// * 1 if signature is valid
/// * 0 if signature is invalid or any error occurred
#[no_mangle]
pub extern "C" fn verify_polkadot_signature(
  address_ptr: *const c_char,
  signature_ptr: *const c_char,
  message_ptr: *const c_char,
) -> u8 {
  // Safety: Convert C strings to Rust strings
  let address = unsafe {
      if address_ptr.is_null() {
          return 0;
      }
      match CStr::from_ptr(address_ptr).to_str() {
          Ok(s) => s,
          Err(_) => return 0,
      }
  };

  let signature_hex = unsafe {
      if signature_ptr.is_null() {
          return 0;
      }
      match CStr::from_ptr(signature_ptr).to_str() {
          Ok(s) => s,
          Err(_) => return 0,
      }
  };

  let message = unsafe {
      if message_ptr.is_null() {
          return 0;
      }
      match CStr::from_ptr(message_ptr).to_str() {
          Ok(s) => s,
          Err(_) => return 0,
      }
  };

  // Parse SS58 address to public key
  let public_key = match Public::from_ss58check_with_version(address) {
      Ok((key, _version)) => key,
      Err(_) => return 0,
  };

  // Parse signature from hex
  let signature_hex_clean = signature_hex.trim_start_matches("0x");
  let signature_bytes = match hex::decode(signature_hex_clean) {
      Ok(bytes) => bytes,
      Err(_) => return 0,
  };

  if signature_bytes.len() != 64 {
      return 0;
  }

  let mut sig_array = [0u8; 64];
  sig_array.copy_from_slice(&signature_bytes);
  let signature = Signature::from_raw(sig_array);

  // Verify the signature
  // Message should be the same format that was signed client-side
  let message_bytes = message.as_bytes();

  if sp_core::sr25519::Pair::verify(&signature, message_bytes, &public_key) {
      1
  } else {
      0
  }
}

/// Get library version (for testing the FFI binding works)
#[no_mangle]
pub extern "C" fn get_version() -> *const c_char {
  "0.1.0\0".as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::ffi::CString;

  #[test]
  fn test_verify_signature() {
      let address = CString::new("5HbqogsYaK54pN3QAgSi4t3Asqditt1X4P7cSBuDt2hPF2BR").unwrap();
      let signature = CString::new("0xf8ce1b80e76bf48a30610d0d3c2c9c8dbfdcb28a9aa8f56ac038d520ff17445ff3ce94809f8479a1224ef0d823d035022a9db2e72bd6c0d2f0244f766dec908b").unwrap();

      // wrapping format first
      let wrapped_message = CString::new("<Bytes>c15335d817e3d3d912d30f5a18a30c30162abc364cd0876d3a94af568d3c8c14</Bytes>").unwrap();

      let result = verify_polkadot_signature(
          address.as_ptr(),
          signature.as_ptr(),
          wrapped_message.as_ptr(),
      );

      eprintln!("Testing with wrapped message:");
      eprintln!("Address: {}", address.to_str().unwrap());
      eprintln!("Signature: {}", signature.to_str().unwrap());
      eprintln!("Message: {}", wrapped_message.to_str().unwrap());
      eprintln!("Result: {}", result);

      if result == 1 {
          eprintln!("✓ Signature valid with <Bytes> wrapping");
          return;
      }

      // Try without wrapping
      let plain_message = CString::new("c15335d817e3d3d912d30f5a18a30c30162abc364cd0876d3a94af568d3c8c14").unwrap();
      let result2 = verify_polkadot_signature(
          address.as_ptr(),
          signature.as_ptr(),
          plain_message.as_ptr(),
      );

      eprintln!("\nTesting with plain message:");
      eprintln!("Message: {}", plain_message.to_str().unwrap());
      eprintln!("Result: {}", result2);

      assert!(result == 1 || result2 == 1, "Signature verification failed with both wrapped and plain message");
  }

  #[test]
  fn test_invalid_signature() {
      let address = CString::new("5HbqogsYaK54pN3QAgSi4t3Asqditt1X4P7cSBuDt2hPF2BR").unwrap();
      // Valid format but wrong signature
      let bad_signature = CString::new("0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
      let message = CString::new("<Bytes>c15335d817e3d3d912d30f5a18a30c30162abc364cd0876d3a94af568d3c8c14</Bytes>").unwrap();

      let result = verify_polkadot_signature(
          address.as_ptr(),
          bad_signature.as_ptr(),
          message.as_ptr(),
      );

      assert_eq!(result, 0, "Invalid signature should return 0");
  }

  #[test]
  fn test_tampered_message() {
      let address = CString::new("5HbqogsYaK54pN3QAgSi4t3Asqditt1X4P7cSBuDt2hPF2BR").unwrap();
      let signature = CString::new("0xf8ce1b80e76bf48a30610d0d3c2c9c8dbfdcb28a9aa8f56ac038d520ff17445ff3ce94809f8479a1224ef0d823d035022a9db2e72bd6c0d2f0244f766dec908b").unwrap();
      // Original message with one character changed (first 'c' -> 'd')
      let tampered_message = CString::new("<Bytes>d15335d817e3d3d912d30f5a18a30c30162abc364cd0876d3a94af568d3c8c14</Bytes>").unwrap();

      let result = verify_polkadot_signature(
          address.as_ptr(),
          signature.as_ptr(),
          tampered_message.as_ptr(),
      );

      assert_eq!(result, 0, "Tampered message should fail verification");
  }

  #[test]
  fn test_wrong_address() {
      // Different address (Alice's well-known dev address)
      let wrong_address = CString::new("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();
      // Valid signature from a different keypair
      let signature = CString::new("0xf8ce1b80e76bf48a30610d0d3c2c9c8dbfdcb28a9aa8f56ac038d520ff17445ff3ce94809f8479a1224ef0d823d035022a9db2e72bd6c0d2f0244f766dec908b").unwrap();
      let message = CString::new("<Bytes>c15335d817e3d3d912d30f5a18a30c30162abc364cd0876d3a94af568d3c8c14</Bytes>").unwrap();

      let result = verify_polkadot_signature(
          wrong_address.as_ptr(),
          signature.as_ptr(),
          message.as_ptr(),
      );

      assert_eq!(result, 0, "Signature verified against wrong address should fail");
  }
}

