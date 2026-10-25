#include "blocktools.hpp"
#include <cstdio>
#include <cstring>
#include <string>

int main() {
  auto v = blocktools::version();
  if (v.empty() || v[0] < '0' || v[0] > '9') {
    std::fprintf(stderr, "FAIL version %s\n", v.c_str());
    return 1;
  }
  auto table = blocktools::chain_table_json();
  if (table.find("\"name\":\"btc\"") == std::string::npos) {
    std::fprintf(stderr, "FAIL table\n");
    return 1;
  }
  auto env = blocktools::envelope_json(R"({"op":"chain_table","chain":"_"})");
  if (env.find("\"status\":\"ok\"") == std::string::npos) {
    std::fprintf(stderr, "FAIL envelope %s\n", env.c_str());
    return 1;
  }
  std::printf("ok  cpp wrapper: version %s table_bytes %zu\n", v.c_str(), table.size());
  return 0;
}
