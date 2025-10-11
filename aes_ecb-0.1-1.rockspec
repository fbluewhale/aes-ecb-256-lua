package = "aes_ecb"
version = "0.1-1"
source = {
  url = ".",
  dir = ".",
}
description = {
  summary = "AES-ECB-256 Lua library (scaffold)",
  detailed = "A small scaffold for building an AES-ECB-256 Lua library with pluggable backends.",
  homepage = "",
  license = "MIT",
}
dependencies = {
  -- add runtime dependencies here, e.g. {"lua-openssl"}
}
build = {
  type = "builtin",
  modules = {
    ["aes_ecb"] = "lua/aes_ecb.lua",
  }
}
