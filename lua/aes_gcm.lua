-- Pure-Lua AES-128-GCM (encrypt-only minimal implementation)
-- Uses AES-128 raw block encryptor and key schedule from `aes_ecb.lua`.
local _M = {}

local aes = require("lua.aes_ecb")
local cipher_block_128 = aes.cipher_block_128
local expand_key_128 = aes.expand_key_128_raw

local function bxor8(a,b)
  local r,p=0,1
  for _=0,7 do
    local abit=a%2; local bbit=b%2
    if abit~=bbit then r=r+p end
    a,b=math.floor(a/2),math.floor(b/2); p=p*2
  end
  return r
end

local function xor_str(a,b)
  local la = math.min(#a,#b)
  local out = {}
  for i=1,la do out[i] = string.char(bxor8(a:byte(i), b:byte(i))) end
  return table.concat(out)
end

local function str_to_bytes(s)
  local t = {}
  for i=1,#s do t[i] = s:byte(i) end
  return t
end

local function bytes_to_str(t)
  for i=1,#t do t[i] = string.char(t[i] % 256) end
  return table.concat(t)
end

-- Bit reflection helper for GCM
local function reflect_byte(b)
  local r = 0
  for i=0,7 do
    if math.floor(b / 2^i) % 2 == 1 then
      r = r + 2^(7-i)
    end
  end
  return r
end

local function reflect_block(arr)
  local out = {}
  for i=1,16 do
    out[17-i] = reflect_byte(arr[i] or 0)
  end
  return out
end

local function xor_bytes_array(a,b)
  local out = {}
  for i=1,16 do out[i] = bxor8(a[i] or 0, b[i] or 0) end
  return out
end

-- Standard GF(2^128) multiplication for GCM (no reflection, standard bit order)
local function gf_mul_bytes(Xbytes, Hbytes)
  local Z = {}
  for i=1,16 do Z[i]=0 end
  local V = {}
  for i=1,16 do V[i]=Hbytes[i] end
  
  -- Process each bit of X from MSB to LSB
  for byte_i=1,16 do
    local b = Xbytes[byte_i] or 0
    for bit=7,0,-1 do
      local xb = math.floor(b / 2^bit) % 2
      if xb == 1 then
        Z = xor_bytes_array(Z, V)
      end
      -- Shift V right by 1 bit
      local carry = 0
      for i=1,16 do
        local v_byte = V[i]
        local new_carry = v_byte % 2
        V[i] = math.floor(v_byte / 2) + carry * 128
        carry = new_carry
      end
      -- If LSB was 1, XOR with R = 11100001 || 0^120
      if carry == 1 then
        V[1] = bxor8(V[1], 0xE1)
      end
    end
  end
  
  return Z
end

local function ghash(H, data)
  local Hb = str_to_bytes(H)
  local Y = {}
  for i=1,16 do Y[i]=0 end
  for i=1,#data,16 do
    local block = data:sub(i,i+15)
    if #block < 16 then block = block .. string.rep('\0', 16 - #block) end
    local B = str_to_bytes(block)
    -- Y = (Y xor B) * H
    local X = xor_bytes_array(Y, B)
    Y = gf_mul_bytes(X, Hb)
  end
  return bytes_to_str(Y)
end

local function inc32(counter)
  local a,b,c,d = counter:byte(13,16)
  local v = ((a*256 + b)*256 + c)*256 + d
  v = (v + 1) % 2^32
  local a1 = math.floor(v / 2^24) % 256
  local b1 = math.floor(v / 2^16) % 256
  local c1 = math.floor(v / 2^8) % 256
  local d1 = v % 256
  return counter:sub(1,12) .. string.char(a1,b1,c1,d1)
end

local function len_block(aad_len, ct_len)
  local function to8(n)
    local parts = {}
    for i=7,0,-1 do parts[#parts+1] = string.char(math.floor(n / 2^ (i*8)) % 256) end
    return table.concat(parts)
  end
  return to8(aad_len) .. to8(ct_len)
end

function _M.encrypt_and_tag(key16, iv12, plaintext)
  assert(#key16 == 16, "key must be 16 bytes")
  assert(#iv12 == 12, "iv must be 12 bytes")
  local w = expand_key_128(key16)
  local H = cipher_block_128(string.rep('\0',16), w)
  local J0 = iv12 .. string.char(0,0,0,1)
  local ciphertext_parts = {}
  local counter = J0
  for i=1,#plaintext,16 do
    counter = inc32(counter)
    local S = cipher_block_128(counter, w)
    local block = plaintext:sub(i,i+15)
    if #block < 16 then block = block .. string.rep('\0', 16 - #block) end
    local ct_block = xor_str(block, S)
    ct_block = ct_block:sub(1, math.min(#plaintext - i + 1, 16))
    ciphertext_parts[#ciphertext_parts+1] = ct_block
  end
  local ciphertext = table.concat(ciphertext_parts)
  local pad_ct = (#ciphertext % 16 == 0) and ciphertext or (ciphertext .. string.rep('\0', 16 - (#ciphertext % 16)))
  local lb = len_block(0, #ciphertext * 8)
  local GH = ghash(H, pad_ct .. lb)
  local E_J0 = cipher_block_128(J0, w)
  local tag = xor_str(E_J0, GH)
  return ciphertext, tag
end

local function to_base64(input)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((input:gsub('.', function(x)
        local r, b_val = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b_val % 2 ^ i - b_val % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
        return b:sub(c + 1, c + 1)
    end) .. ({ '', '==', '=' })[#input % 3 + 1])
end

function _M.AES_128_and_base64(secret_key, vektor, text)
    local encrypted, tag = _M.encrypt_and_tag(secret_key, vektor, text)
    local result = encrypted .. tag
    local encrypted_base64 = to_base64(result)
    return encrypted_base64
end

return _M
