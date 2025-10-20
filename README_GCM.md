# AES-128-GCM Pure Lua Implementation

This module provides a **pure Lua** implementation of AES-128-GCM (Galois/Counter Mode) encryption. It requires no external dependencies (no FFI, no bit library) and works with Lua 5.1+.

## Features

- ✅ Pure Lua implementation (no C dependencies)
- ✅ AES-128-GCM authenticated encryption
- ✅ Compatible with Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT
- ✅ Returns ciphertext + 16-byte authentication tag
- ✅ Base64 encoding support

## Usage

### Basic Example

```lua
local aes_gcm = require("lua.aes_gcm")

local secret_key = "1234567890123456"  -- 16 bytes
local nonce = "123456789012"           -- 12 bytes
local plaintext = "Hello, World!"

-- Option 1: Get base64-encoded result (ciphertext + tag)
local encrypted_base64 = aes_gcm.AES_128_and_base64(secret_key, nonce, plaintext)
print("Encrypted:", encrypted_base64)

-- Option 2: Get separate ciphertext and tag
local ciphertext, tag = aes_gcm.encrypt_and_tag(secret_key, nonce, plaintext)
print("Ciphertext length:", #ciphertext)
print("Tag length:", #tag)  -- always 16 bytes
```

## API Reference

### `aes_gcm.encrypt_and_tag(key16, iv12, plaintext)`

Encrypts plaintext using AES-128-GCM.

**Parameters:**
- `key16` (string): 16-byte encryption key (raw bytes)
- `iv12` (string): 12-byte initialization vector / nonce (raw bytes)
- `plaintext` (string): Data to encrypt

**Returns:**
- `ciphertext` (string): Encrypted data (same length as plaintext)
- `tag` (string): 16-byte authentication tag

### `aes_gcm.AES_128_and_base64(secret_key, vektor, text)`

Convenience function that encrypts and returns Base64-encoded result.

**Parameters:**
- `secret_key` (string): 16-byte encryption key
- `vektor` (string): 12-byte nonce/IV
- `text` (string): Plaintext to encrypt

**Returns:**
- `encrypted_base64` (string): Base64-encoded (ciphertext || tag)

## Implementation Details

- **Mode**: GCM (Galois/Counter Mode)
- **Key size**: 128 bits (16 bytes)
- **IV/Nonce size**: 96 bits (12 bytes) - standard for GCM
- **Tag size**: 128 bits (16 bytes)
- **AAD**: Not currently supported (empty)

### GHASH Implementation

The GHASH authentication function is implemented using byte-array operations to avoid precision issues with Lua numbers. The GF(2^128) multiplication uses the standard shift-and-reduce algorithm with the reduction polynomial `x^128 + x^7 + x^2 + x + 1`.

## Examples

See:
- `scripts/smoke_gcm.lua` - Basic smoke test
- `scripts/example_gcm.lua` - Comprehensive examples

## Comparison with FFI-based Implementation

The provided sample uses FFI to call OpenSSL's `EVP_aes_128_gcm()`. This pure Lua implementation:

- ✅ Works without FFI or OpenSSL
- ✅ Portable across all Lua implementations
- ❌ Significantly slower than native C code

For production use cases requiring high performance, consider the FFI-based approach. For portability or educational purposes, this pure Lua implementation is ideal.

## Testing

Run the smoke test:

```bash
lua scripts/smoke_gcm.lua
```

Run examples:

```bash
lua scripts/example_gcm.lua
```

## License

Same as parent project (see LICENSE).
