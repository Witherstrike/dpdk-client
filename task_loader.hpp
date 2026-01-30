#include <cstdint>
#include <fstream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <tuple>

using V = std::tuple<uint32_t, uint32_t, uint8_t>;
using M = std::map<std::string, std::list<V>>;
using CV = std::tuple<std::string, uint16_t, uint16_t>;
using C = std::vector<CV>;

static inline void trim(std::string &s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    s.erase(0, i);
}

static inline uint32_t parse_u32(const std::string &t) {
    int base = (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) ? 16 : 10;
    return static_cast<uint32_t>(std::stoul(t, nullptr, base));
}

static inline uint16_t parse_u16(const std::string &t) {
    return static_cast<uint16_t>(parse_u32(t));
}

static inline uint8_t parse_u8(const std::string &t) {
    return static_cast<uint8_t>(parse_u32(t));
}

M load_tasks(const std::string &path) {
    std::ifstream in(path);
    M m;

    std::string line, curKey;
    while (std::getline(in, line)) {
        trim(line);
        if (line.empty()) continue;

        if (line.back() == ':') {
            curKey = line.substr(0, line.size() - 1);
            (void)m[curKey];
            continue;
        }

        std::istringstream iss(line);
        std::string ta, tb, tc;
        iss >> ta >> tb >> tc;

        m[curKey].push_back(V{ parse_u32(ta), parse_u32(tb), parse_u8(tc) });
    }
    return m;
}

C load_config(const std::string &path) {
    std::ifstream in(path);
    C c;

    std::string line;
    while (std::getline(in, line)) {
        trim(line);
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string ta, tb, tc;
        iss >> ta >> tb >> tc;

        c.push_back(CV{ ta, parse_u16(tb), parse_u16(tc) });
    }
    return c;
}