#pragma once
// Thin C++ wrapper over the blocktools C ABI (secrets-off).
#include "blocktools.h"
#include <stdexcept>
#include <string>

namespace blocktools {

inline std::string version() {
  const char *v = bt_version();
  return v ? std::string(v) : std::string();
}

inline std::string chain_table_json() {
  char *p = bt_chain_table();
  if (!p) throw std::runtime_error("bt_chain_table returned null");
  std::string s(p);
  bt_free(p);
  return s;
}

inline std::string envelope_json(const std::string &req) {
  char *p = bt_envelope(req.c_str());
  if (!p) throw std::runtime_error("bt_envelope returned null");
  std::string s(p);
  bt_free(p);
  return s;
}

} // namespace blocktools
