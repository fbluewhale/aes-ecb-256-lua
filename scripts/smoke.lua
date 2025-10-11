
local AESCipher = require("lua.aes_ecb")

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

local key_raw = random_bytes(32)
local key_b64 = encode_b64(key_raw)
print("using random Base64 key:", key_b64)

local inst = AESCipher.new(key_b64)
local pt = "hello smoke test"
local ct = inst:encrypt(pt)
local dt, err = inst:decrypt(ct)
if not dt then
  io.stderr:write("decrypt error: ", tostring(err), "\n")
end

print("plaintext:", pt)
print("ciphertext:", ct)
print("decrypted:", dt)
print("roundtrip ok:", dt == pt)

os.exit(dt == pt and 0 or 1)
