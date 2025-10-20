A minimal Lua library scaffold for AES-ECB-256 and AES-ECB-128 implementations.

This repository contains a base template you can extend with a real crypto backend (OpenSSL / LuaCrypto / LuaSec / LuaJIT-ffi).

Important: this implementation is pure Lua and dependency-free, and is compatible with Lua 5.1. That makes it suitable for embedding in OpenResty or APISIX (both run Lua 5.1). Because it's written in plain Lua it has no native module requirements; however, it will be slower than native C/FFI-based implementations.

Highlights

- `lua/aes_ecb.lua` — Pure-Lua AES-256-ECB and AES-128-ECB implementations (PKCS#7 padding, Base64 codec)
- `spec/` — busted tests (unit tests for both AES-256 and AES-128)
- `scripts/smoke.lua` — smoke test with random key generation
- `aes_ecb-0.1-1.rockspec` — simple rockspec for publishing
- `.github/workflows/test.yml` — CI workflow to run busted tests
- `.luacheckrc` — basic lint config (Lua 5.1)

Quick start

1. Install dependencies (example using Lua 5.1 and luarocks):

```bash
# install busted for tests
luarocks install --local busted
```

2. Run tests

```bash
# from repo root
busted
```

3. Use the module

```lua
local aes = require("aes_ecb")

-- AES-256-ECB (32-byte key, 14 rounds)
local cipher256 = aes.AES256.new("BASE64_ENCODED_32_BYTE_KEY")
local ct256 = cipher256:encrypt("hello world")
local pt256 = cipher256:decrypt(ct256)

-- AES-128-ECB (16-byte key, 10 rounds)
local cipher128 = aes.AES128.new("BASE64_ENCODED_16_BYTE_KEY")
local ct128 = cipher128:encrypt("hello world")
local pt128 = cipher128:decrypt(ct128)

-- Legacy API (defaults to AES-256)
local cipher = aes.new("BASE64_KEY")
```

Next steps

- Plug a real crypto backend (see `lua/aes_ecb.lua` for details)
- Add examples and integration tests
- Publish a rockspec and CI badges

License: MIT
