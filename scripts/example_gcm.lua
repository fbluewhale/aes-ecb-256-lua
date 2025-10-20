-- Example demonstrating AES-128-GCM encryption with pure Lua
local aes_gcm = require("lua.aes_gcm")

-- Example 1: Using the convenience function (like the FFI sample)
print("=== Example 1: AES_128_and_base64 ===")
local secret_key = "1234567890123456"  -- 16 bytes
local vektor = "123456789012"          -- 12 bytes (nonce/IV)
local text = "Hello, World!"

local encrypted_base64 = aes_gcm.AES_128_and_base64(secret_key, vektor, text)
print("Plaintext: " .. text)
print("Encrypted (base64): " .. encrypted_base64)

-- Example 2: Using the low-level encrypt_and_tag function
print("\n=== Example 2: encrypt_and_tag (separate ciphertext and tag) ===")
local key = string.rep("\1", 16)  -- 16-byte key
local iv = string.rep("\2", 12)   -- 12-byte IV
local plaintext = "Pure Lua AES-GCM implementation"

local ciphertext, tag = aes_gcm.encrypt_and_tag(key, iv, plaintext)
print("Plaintext: " .. plaintext)
print("Ciphertext length: " .. #ciphertext .. " bytes")
print("Tag length: " .. #tag .. " bytes")

-- Convert to hex for display
local function to_hex(s)
  local hex = {}
  for i=1,#s do hex[i] = string.format("%02x", s:byte(i)) end
  return table.concat(hex)
end

print("Ciphertext (hex): " .. to_hex(ciphertext))
print("Tag (hex): " .. to_hex(tag))

print("\n✓ AES-128-GCM encryption successful!")
