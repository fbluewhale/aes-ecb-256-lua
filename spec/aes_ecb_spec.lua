local aes = require("aes_ecb")
local AES256 = aes.AES256
local AES128 = aes.AES128

describe("aes_ecb base scaffold", function()
  it("validates AES-256 key", function()
    -- AES256.new accepts Base64 keys and normalizes them
    local inst = AES256.new()  -- use default key
    assert.is_not_nil(inst)
    local inst2 = AES256.new("Y0hKbmJYaDBVV1V6TVc1amJreHVkVGxX")  -- valid Base64
    assert.is_not_nil(inst2)
  end)

  it("pads and unpads correctly", function()
    local cases = {
      {"", 16},
      {"a", 15},
      {string.rep("x", 16), 16},
      {string.rep("y", 17), 15},
    }
    for _, tc in ipairs(cases) do
      local data, expectedPad = tc[1], tc[2]
      local padded = aes.pkcs7_pad(data)
      assert.are.equal(#padded % 16, 0)
      local unp = aes.pkcs7_unpad(padded)
      assert.are.equal(unp, data)
    end
  end)

  it("encrypts and decrypts AES-256 roundtrip", function()
    local inst = AES256.new()  -- use default key
    local pt = "hello world"
    local ct = inst:encrypt(pt)
    local dt = inst:decrypt(ct)
    assert.are.equal(pt, dt)
  end)

  it("encrypts and decrypts AES-128 roundtrip", function()
    local inst = AES128.new()  -- use default key (normalized to 16 bytes)
    local pt = "hello world aes128"
    local ct = inst:encrypt(pt)
    local dt = inst:decrypt(ct)
    assert.are.equal(pt, dt)
  end)
end)
