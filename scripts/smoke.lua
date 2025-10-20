
local aes = require("lua.aes_ecb")

-- generate a random 32-byte key and Base64-encode it
math.randomseed(os.time() + (os.clock() * 1000000))
local function random_bytes(n)
  local t = {}
  for i = 1, n do t[i] = string.char(math.random(0, 255)) end
  return table.concat(t)
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function encode_b64(bin)
  local pad = (3 - (#bin % 3)) % 3
  if pad > 0 then bin = bin .. string.rep("\0", pad) end
  local out = {}
  for i = 1, #bin, 3 do
    local b1, b2, b3 = bin:byte(i, i + 2)
    b1 = b1 or 0; b2 = b2 or 0; b3 = b3 or 0
    local n = b1 * 65536 + b2 * 256 + b3
    local c1 = math.floor(n / 262144) % 64 + 1 -- 2^18
    local c2 = math.floor(n / 4096) % 64 + 1   -- 2^12
    local c3 = math.floor(n / 64) % 64 + 1     -- 2^6
    local c4 = n % 64 + 1
    out[#out + 1] = B64:sub(c1, c1)
    out[#out + 1] = B64:sub(c2, c2)
    out[#out + 1] = B64:sub(c3, c3)
    out[#out + 1] = B64:sub(c4, c4)
  end
  if pad > 0 then out[#out] = "=" end
  if pad == 2 then out[#out - 1] = "=" end
  return table.concat(out)
end

print("=== AES-256-ECB ===")
local key256_raw = random_bytes(32)
local key256_b64 = encode_b64(key256_raw)
print("Random Base64 key (256-bit):", key256_b64)

local inst256 = aes.AES256.new(key256_b64)
local pt256 = "hello smoke test 256"
local ct256 = inst256:encrypt(pt256)
local dt256 = inst256:decrypt(ct256)

print("plaintext:", pt256)
print("ciphertext:", ct256)
print("decrypted:", dt256)
print("roundtrip ok:", dt256 == pt256)

print("\n=== AES-128-ECB ===")
local key128_raw = random_bytes(16)
local key128_b64 = encode_b64(key128_raw)
print("Random Base64 key (128-bit):", key128_b64)

local inst128 = aes.AES128.new(key128_b64)
local pt128 = "hello smoke test 128"
local ct128 = inst128:encrypt(pt128)
local dt128 = inst128:decrypt(ct128)

print("plaintext:", pt128)
print("ciphertext:", ct128)
print("decrypted:", dt128)
print("roundtrip ok:", dt128 == pt128)

os.exit((dt256 == pt256 and dt128 == pt128) and 0 or 1)
