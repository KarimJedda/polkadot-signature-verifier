# frozen_string_literal: true

require 'ffi'

module PolkadotSignatureVerifier
  extend FFI::Library

  # Try to load from multiple possible locations
  LIB_PATHS = [
    File.expand_path('../target/release/libpolkadot_signature_verifier.so', __dir__),     # Linux
    File.expand_path('../target/release/libpolkadot_signature_verifier.dylib', __dir__),  # macOS
    File.expand_path('../target/release/polkadot_signature_verifier.dll', __dir__),       # Windows
  ]

  lib_path = LIB_PATHS.find { |path| File.exist?(path) }

  if lib_path.nil?
    raise LoadError, "Could not find polkadot-signature-verifier library in any of: #{LIB_PATHS.join(', ')}"
  end

  ffi_lib lib_path

  # Attach the verification function
  # Returns 1 for valid, 0 for invalid
  attach_function :verify_polkadot_signature, [:string, :string, :string], :uint8
  attach_function :get_version, [], :string

  # Ruby-friendly wrapper
  # Automatically wraps message in <Bytes>...</Bytes> as per Polkadot signing format
  def self.verify(address:, signature:, message:)
    wrapped_message = "<Bytes>#{message}</Bytes>"
    result = verify_polkadot_signature(address, signature, wrapped_message)
    result == 1
  end

  # Check if the library loaded correctly
  def self.test_connection
    version = get_version
    puts "Polkadot Signature Verifier v#{version} loaded successfully"
    true
  rescue => e
    puts "Failed to connect to library: #{e.message}"
    false
  end
end

