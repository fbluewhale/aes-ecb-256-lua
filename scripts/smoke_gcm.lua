local aes_gcm = require("lua.aes_gcm")

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function encode_b64(bin)
  local pad = (3 - (#bin % 3)) % 3
  if pad > 0 then bin = bin .. string.rep("\0", pad) end
  local out={}
  for i=1,#bin,3 do
    local b1,b2,b3 = bin:byte(i,i+2)
    b1=b1 or 0; b2=b2 or 0; b3=b3 or 0
    local n = b1*65536 + b2*256 + b3
    out[#out+1]=B64:sub(math.floor(n/262144)%64+1,math.floor(n/262144)%64+1)
    out[#out+1]=B64:sub(math.floor(n/4096)%64+1,math.floor(n/4096)%64+1)
    out[#out+1]=B64:sub(math.floor(n/64)%64+1,math.floor(n/64)%64+1)
    out[#out+1]=B64:sub(n%64+1,n%64+1)
  end
  if pad>0 then out[#out]="=" end
  if pad==2 then out[#out-1]="=" end
  return table.concat(out)
end

local key = string.rep("A", 16) -- example 16-byte key
local iv  = string.rep("B", 12) -- example 12-byte IV
local plaintext = "Hello, AES-GCM from pure Lua!"

local ct, tag = aes_gcm.encrypt_and_tag(key, iv, plaintext)
local combined = ct .. tag
print("ciphertext+tag (base64):", encode_b64(combined))
print("key (base64):", encode_b64(key)," iv (base64):", encode_b64(iv)  )
