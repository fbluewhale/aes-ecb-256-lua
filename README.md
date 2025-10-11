# aes_ecb

A minimal Lua library scaffold for an AES-ECB-256 implementation.

This repository contains a base template you can extend with a real crypto backend (OpenSSL / LuaCrypto / LuaSec / LuaJIT-ffi).

Important: this implementation is pure Lua and dependency-free, and is compatible with Lua 5.1. That makes it suitable for embedding in OpenResty or APISIX (both run Lua 5.1). Because it's written in plain Lua it has no native module requirements; however, it will be slower than native C/FFI-based implementations.

Highlights

- `lua/aes_ecb.lua` — module skeleton and helper functions (padding, key validation, pluggable backend)
- `spec/` — busted tests (unit tests)
- `aes_ecb-0.1-1.rockspec` — simple rockspec for publishing
- `.github/workflows/test.yml` — CI workflow to run busted tests
- `.luacheckrc` — basic lint config

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
-- set a crypto backend (recommended) or implement encrypt/decrypt
-- aes.set_backend(my_backend)

local ok, err = pcall(function()
  -- create instance with a Base64-encoded 32-byte key (or omit to use the built-in fixed key)
  local key_b64 = "<BASE64_32_BYTE_KEY>"
  local c = aes.new(key_b64)
  local ct = c:encrypt("hello world")
end)
```

Next steps

- Plug a real crypto backend (see `lua/aes_ecb.lua` for details)
- Add examples and integration tests
- Publish a rockspec and CI badges

License: MIT
