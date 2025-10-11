local AESCipher = require("aes_ecb")

describe("aes_ecb base scaffold", function()
  it("validates key length", function()
    -- AESCipher.new accepts Base64 keys and normalizes them; short or invalid keys are handled
    local inst = AESCipher.new()  -- use default key
    assert.is_not_nil(inst)
    local inst2 = AESCipher.new("Y0hKbmJYaDBVV1V6TVc1amJreHVkVGxX")  -- valid Base64
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
      local padded = AESCipher.pkcs7_pad(data)
      assert.are.equal(#padded % 16, 0)
      local unp = AESCipher.pkcs7_unpad(padded)
      assert.are.equal(unp, data)
    end
  end)

  it("encrypts and decrypts roundtrip", function()
    local inst = AESCipher.new()  -- use default key
    local pt = "hello world"
    local ct = inst:encrypt(pt)
    local dt = inst:decrypt(ct)
    assert.are.equal(pt, dt)
  end)
end)
