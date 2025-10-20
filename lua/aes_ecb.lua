--[[---------------------------------------------------------------------------
  Pure-Lua AES-256-ECB (Lua 5.1 – no bit/ffi)
  • PKCS#7 padding
  • standard Base64 codec (RFC 4648)
  • slow but dependency-free
---------------------------------------------------------------------------]]--

local AESCipher = {};  AESCipher.__index = AESCipher

------------------------------------------------------------------------
-- section 1 : tiny bitwise helpers (8- and 32-bit) -------------------
------------------------------------------------------------------------
local function bxor2(a,b)               -- 8-bit XOR of two bytes
  local r,p=0,1
  for _=0,7 do
    local abit=a%2; local bbit=b%2
    if abit~=bbit then r=r+p end
    a,b=math.floor(a/2),math.floor(b/2); p=p*2
  end
  return r
end
local function bxor(a,b,...)            -- variadic XOR for bytes
  local r = bxor2(a or 0, b or 0)
  local t = {...}
  for i=1,#t do r = bxor2(r, t[i] or 0) end
  return r
end
local function band(a,b)               -- 8-bit AND
  local r,p=0,1
  for _=0,7 do
    local abit=a%2; local bbit=b%2
    if abit==1 and bbit==1 then r=r+p end
    a,b=math.floor(a/2),math.floor(b/2); p=p*2
  end
  return r
end
local function lshift8(x,n) return (x * 2^n) % 256 end
local function rshift8(x,n) return math.floor(x / 2^n) end

-- 32-bit helpers (for key schedule) -----------------------------------
local MOD32 = 2^32
local function add32(a,b) return (a+b) % MOD32 end
local function xor32(a,b)
  local res,p=0,1
  for _=0,31 do
    local abit=a%2; local bbit=b%2
    if abit~=bbit then res=res+p end
    a,b=math.floor(a/2),math.floor(b/2); p=p*2
  end
  return res
end
local function bor32(a,b)
  local res,p=0,1
  for _=0,31 do
    local abit=a%2; local bbit=b%2
    if abit==1 or bbit==1 then res=res+p end
    a,b=math.floor(a/2),math.floor(b/2); p=p*2
  end
  return res
end
local function lshift32(x,n) return (x * 2^n) % MOD32 end
local function rshift32(x,n) return math.floor(x / 2^n) end

------------------------------------------------------------------------
-- section 2 : AES constants (S-box, inverse, Rcon) --------------------
------------------------------------------------------------------------
local S = { -- Correct 256-byte forward S-box (dec)
  99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
 202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
 183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
   4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
   9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
  83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
 208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
  81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
 205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
  96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
 224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
 231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
 186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
 112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
 225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
 140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22
}
local invS = {}       -- build inverse S-box (1-based indexing)
for i=0,255 do invS[S[i+1]+1] = i end
local Rcon = {0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
              0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000}

------------------------------------------------------------------------
-- section 3 : key expansion (AES-256 → 60 words) ----------------------
------------------------------------------------------------------------
local function bytes_to_word(b1,b2,b3,b4)
  return ((b1*256 + b2)*256 + b3)*256 + b4
end
local function word_to_bytes(w)
  local b4 = w % 256; w = math.floor(w/256)
  local b3 = w % 256; w = math.floor(w/256)
  local b2 = w % 256; w = math.floor(w/256)
  local b1 = w % 256
  return b1,b2,b3,b4
end
local function subword(w)
  local b1,b2,b3,b4 = word_to_bytes(w)
  return bytes_to_word(S[b1+1],S[b2+1],S[b3+1],S[b4+1])
end
local function rotword(w)
  return bor32(lshift32(w,8), rshift32(w,24))
end

local function expand_key(key32)  -- key32: 32 raw bytes (AES-256: 60 words)
  local w = {}
  for i=0,7 do
    local b1,b2,b3,b4 = key32:byte(4*i+1,4*i+4)
    w[i] = bytes_to_word(b1,b2,b3,b4)
  end
  for i=8,59 do
    local tmp = w[i-1]
    if i % 8 == 0 then
      tmp = xor32(subword(rotword(tmp)), Rcon[math.floor(i/8)])
    elseif i % 8 == 4 then
      tmp = subword(tmp)
    end
    w[i] = xor32(w[i-8], tmp)
  end
  return w
end

local function expand_key_128(key16)  -- key16: 16 raw bytes (AES-128: 44 words)
  local w = {}
  for i=0,3 do
    local b1,b2,b3,b4 = key16:byte(4*i+1,4*i+4)
    w[i] = bytes_to_word(b1,b2,b3,b4)
  end
  for i=4,43 do
    local tmp = w[i-1]
    if i % 4 == 0 then
      tmp = xor32(subword(rotword(tmp)), Rcon[math.floor(i/4)])
    end
    w[i] = xor32(w[i-4], tmp)
  end
  return w
end

------------------------------------------------------------------------
-- section 4 : state helpers (16-byte array) ---------------------------
------------------------------------------------------------------------
local function add_round_key(state, w, round)
  for c=0,3 do
    local k = w[round*4+c]
    local a,b,c1,d = word_to_bytes(k)
    local i = c*4+1
    state[i]   = bxor(state[i]  ,a)
    state[i+1] = bxor(state[i+1],b)
    state[i+2] = bxor(state[i+2],c1)
    state[i+3] = bxor(state[i+3],d)
  end
end

local function sub_bytes(state,box)
  for i=1,16 do state[i] = box[state[i]+1] end
end

local function shift_rows(state,inv)
  local s = state
  if not inv then
    s[2],s[6],s[10],s[14] = s[6],s[10],s[14],s[2]
    s[3],s[7],s[11],s[15] = s[11],s[15],s[3],s[7]
    s[4],s[8],s[12],s[16] = s[16],s[4],s[8],s[12]
  else
    s[6],s[10],s[14],s[2] = s[2],s[6],s[10],s[14]
    s[11],s[15],s[3],s[7] = s[3],s[7],s[11],s[15]
    s[16],s[4],s[8],s[12] = s[4],s[8],s[12],s[16]
  end
end

-- GF(2^8) multiply via Russian peasant method
local function gmul(a,b)
  local p=0
  for _=1,8 do
    if band(b,1)==1 then p=bxor(p,a) end
    local hi = band(a,0x80)
    a = (a*2)%256
    if hi~=0 then a=bxor(a,0x1b) end
    b = rshift8(b,1)
  end
  return p
end

local function mix_columns(state,inv)
  for c=0,3 do
    local i=4*c+1
    local a,b,c1,d = state[i],state[i+1],state[i+2],state[i+3]
    if not inv then
      state[i]   = bxor(gmul(a,2), gmul(b,3), c1, d)
      state[i+1] = bxor(a, gmul(b,2), gmul(c1,3), d)
      state[i+2] = bxor(a, b, gmul(c1,2), gmul(d,3))
      state[i+3] = bxor(gmul(a,3), b, c1, gmul(d,2))
    else
      state[i]   = bxor(gmul(a,0x0e), gmul(b,0x0b), gmul(c1,0x0d), gmul(d,0x09))
      state[i+1] = bxor(gmul(a,0x09), gmul(b,0x0e), gmul(c1,0x0b), gmul(d,0x0d))
      state[i+2] = bxor(gmul(a,0x0d), gmul(b,0x09), gmul(c1,0x0e), gmul(d,0x0b))
      state[i+3] = bxor(gmul(a,0x0b), gmul(b,0x0d), gmul(c1,0x09), gmul(d,0x0e))
    end
  end
end

local function cipher_block(inp, w)
  local s={inp:byte(1,16)}
  add_round_key(s,w,0)
  for r=1,13 do
    sub_bytes(s,S); shift_rows(s,false); mix_columns(s,false)
    add_round_key(s,w,r)
  end
  sub_bytes(s,S); shift_rows(s,false); add_round_key(s,w,14)
  return string.char(unpack(s))
end

local function inv_cipher_block(inp,w)
  local s={inp:byte(1,16)}
  add_round_key(s,w,14)
  for r=13,1,-1 do
    shift_rows(s,true); sub_bytes(s,invS); add_round_key(s,w,r)
    mix_columns(s,true)
  end
  shift_rows(s,true); sub_bytes(s,invS); add_round_key(s,w,0)
  return string.char(unpack(s))
end

-- AES-128 cipher functions (10 rounds)
local function cipher_block_128(inp, w)
  local s={inp:byte(1,16)}
  add_round_key(s,w,0)
  for r=1,9 do
    sub_bytes(s,S); shift_rows(s,false); mix_columns(s,false)
    add_round_key(s,w,r)
  end
  sub_bytes(s,S); shift_rows(s,false); add_round_key(s,w,10)
  return string.char(unpack(s))
end

local function inv_cipher_block_128(inp,w)
  local s={inp:byte(1,16)}
  add_round_key(s,w,10)
  for r=9,1,-1 do
    shift_rows(s,true); sub_bytes(s,invS); add_round_key(s,w,r)
    mix_columns(s,true)
  end
  shift_rows(s,true); sub_bytes(s,invS); add_round_key(s,w,0)
  return string.char(unpack(s))
end

------------------------------------------------------------------------
-- section 5 : base-64 helpers (RFC 4648, no external libs) ------------
------------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local rev = {}; for i=1,#B64 do rev[B64:sub(i,i)]=i-1 end

local function encode_b64(bin)
  local pad = (3 - (#bin % 3)) % 3
  if pad > 0 then bin = bin .. string.rep("\0", pad) end
  local out={}
  for i=1,#bin,3 do
    local n = bin:byte(i)*65536 + bin:byte(i+1)*256 + bin:byte(i+2)
    out[#out+1]=B64:sub(rshift32(n,18)%64+1,rshift32(n,18)%64+1)
    out[#out+1]=B64:sub(rshift32(n,12)%64+1,rshift32(n,12)%64+1)
    out[#out+1]=B64:sub(rshift32(n,6)%64+1 ,rshift32(n,6)%64+1 )
    out[#out+1]=B64:sub(n%64+1,n%64+1)
  end
  if pad>0 then out[#out]   = "=" end
  if pad==2 then out[#out-1]= "=" end
  return table.concat(out)
end

local function decode_b64(str)
  str = (str or ""):gsub("%s","")
  local out={}
  for i=1,#str,4 do
    local c1 = str:sub(i,i);   local c2 = str:sub(i+1,i+1)
    local c3 = str:sub(i+2,i+2); local c4 = str:sub(i+3,i+3)
    local n = lshift32(rev[c1] or 0,18) + lshift32(rev[c2] or 0,12)
            + (c3 ~= "=" and c3 ~= "" and lshift32(rev[c3] or 0,6) or 0)
            + (c4 ~= "=" and c4 ~= "" and (rev[c4] or 0) or 0)
    out[#out+1]=string.char(rshift32(n,16)%256)
    if c3 ~= "=" and c3 ~= "" then out[#out+1]=string.char(rshift32(n,8)%256) end
    if c4 ~= "=" and c4 ~= "" then out[#out+1]=string.char(n%256) end
  end
  return table.concat(out)
end

------------------------------------------------------------------------
-- section 6 : public methods ------------------------------------------
------------------------------------------------------------------------
local FIXED_KEY_B64 = "TEST_KEY_1234567890_12345678"  -- given key (Base64)

local function normalize_key_b64(b64)
  local raw = decode_b64(b64 or "")
  if #raw < 32 then
    raw = raw .. string.rep("\0", 32 - #raw)     -- right-pad with NULs
  elseif #raw > 32 then
    raw = raw:sub(1,32)                          -- truncate
  end
  return raw
end

function AESCipher.new(key_b64)
  -- Accept a Base64-encoded key (or nil). Normalize to 32 raw bytes.
  local key32 = normalize_key_b64(key_b64 or FIXED_KEY_B64)
  local self = setmetatable({}, AESCipher)
  self._w = expand_key(key32)                    -- 32 bytes
  return self
end

local function pkcs7_pad(msg)
  local p = 16 - (#msg % 16)
  return msg .. string.rep(string.char(p),p)
end
local function pkcs7_unpad(data)
  local len = #data
  if len == 0 then return "" end
  -- use explicit positive index for Lua 5.1 compatibility
  local p = data:byte(len)
  if p < 1 or p > 16 then return nil, "bad padding" end
  if len < p then return nil, "bad padding" end
  for i = len - p + 1, len do
    if data:byte(i) ~= p then return nil, "bad padding" end
  end
  return data:sub(1, len - p)
end

function AESCipher:encrypt(plain)
  local data = pkcs7_pad(plain)
  local out={}
  for i=1,#data,16 do
    out[#out+1]= cipher_block(data:sub(i,i+15), self._w)
  end
  return encode_b64(table.concat(out))
end

function AESCipher:decrypt(token)
  local raw = decode_b64(token)
  if (#raw%16)~=0 then return nil,"bad ciphertext len" end
  local out={}
  for i=1,#raw,16 do
    out[#out+1]= inv_cipher_block(raw:sub(i,i+15), self._w)
  end
  return pkcs7_unpad(table.concat(out))
end

-- Export helpers for testing
AESCipher.pkcs7_pad = pkcs7_pad
AESCipher.pkcs7_unpad = pkcs7_unpad

------------------------------------------------------------------------
-- section 6b : AES-128-ECB (10 rounds, 16-byte key) ------------------
------------------------------------------------------------------------
local AES128Cipher = {}; AES128Cipher.__index = AES128Cipher

local function normalize_key_b64_128(b64)
  local raw = decode_b64(b64 or "")
  if #raw < 16 then
    raw = raw .. string.rep("\0", 16 - #raw)     -- right-pad with NULs
  elseif #raw > 16 then
    raw = raw:sub(1,16)                          -- truncate to 16 bytes
  end
  return raw
end

function AES128Cipher.new(key_b64)
  -- Accept a Base64-encoded key (or nil). Normalize to 16 raw bytes for AES-128.
  local key16 = normalize_key_b64_128(key_b64 or FIXED_KEY_B64)
  local self = setmetatable({}, AES128Cipher)
  self._w = expand_key_128(key16)                -- 16 bytes, 44 words
  return self
end

function AES128Cipher:encrypt(plain)
  local data = pkcs7_pad(plain)
  local out={}
  for i=1,#data,16 do
    out[#out+1]= cipher_block_128(data:sub(i,i+15), self._w)
  end
  return encode_b64(table.concat(out))
end

function AES128Cipher:decrypt(token)
  local raw = decode_b64(token)
  if (#raw%16)~=0 then return nil,"bad ciphertext len" end
  local out={}
  for i=1,#raw,16 do
    out[#out+1]= inv_cipher_block_128(raw:sub(i,i+15), self._w)
  end
  return pkcs7_unpad(table.concat(out))
end

-- Export helpers
AES128Cipher.pkcs7_pad = pkcs7_pad
AES128Cipher.pkcs7_unpad = pkcs7_unpad

------------------------------------------------------------------------
-- Return both AES-256 and AES-128 classes
------------------------------------------------------------------------
return {
  AES256 = AESCipher,
  AES128 = AES128Cipher,
  new = AESCipher.new,        -- legacy: default to AES-256
  new_256 = AESCipher.new,
  new_128 = AES128Cipher.new,
  -- expose raw block encryptor for AES-128 (pure-Lua use)
  cipher_block_128 = cipher_block_128,
  -- expose expand_key_128 to allow raw-key block encryption
  expand_key_128_raw = expand_key_128,
  pkcs7_pad = pkcs7_pad,
  pkcs7_unpad = pkcs7_unpad,
}
