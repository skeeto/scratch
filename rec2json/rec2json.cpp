// This is free and unencumbered software released into the public domain.
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iostream>
#include <span>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

enum Token : std::ptrdiff_t {};
using Str = std::string_view;
using StrTableKey = std::tuple<Token, Str>;

template<>
struct std::hash<StrTableKey> {
    std::size_t operator()(StrTableKey const& k) const noexcept
    {
        std::uint64_t k1 = static_cast<std::uint64_t>(std::get<0>(k));
        std::uint64_t k2 = std::hash<Str>{}(std::get<1>(k));
        std::uint64_t r  = k1*1111111111111111111u + k2;
        return static_cast<std::size_t>(r>>32 ^ r);
    }
};

struct StrTable {
    std::unordered_map<StrTableKey, Token> table;
    std::vector<Str> strings;

    Token intern(Token ns, Str s)
    {
        Token& token = table[{ns, s}];
        if (!token) {
            strings.push_back(s);
            token = Token{static_cast<std::ptrdiff_t>(strings.size())};
        }
        return token;
    }

    Str operator[](Token t) const
    {
        return strings[t-1];
    }
};

struct Field {
    Str name;
    size_t index;
    std::vector<Token> tokens;

    Field(Str name, std::size_t index, StrTable& t): name{name}, index{index}
    {
        Token ns{};
        std::size_t prev = 0;
        for (std::size_t i = 0; i < name.size(); i++) {
            if (name[i] == '.') {
                auto sub = name.substr(prev, i-prev);
                ns = t.intern(ns, sub);
                tokens.push_back(ns);
                prev = i + 1;
            }
        }
        auto sub = name.substr(prev, name.size()-prev);
        tokens.push_back(t.intern(ns, sub));
    }

    bool operator<(Field const& other) const
    {
        std::size_t i = 0;
        for (; i<tokens.size() && i<other.tokens.size(); i++) {
            if (tokens[i] != other.tokens[i]) {
                return tokens[i] < other.tokens[i];
            }
        }
        return tokens.size() < other.tokens.size();
    }
};

struct Headers {
    std::vector<Field> fields;
    StrTable table;
};

inline Headers parse_header(Str header)
{
    Headers r;

    std::size_t prev = 0;
    for (std::size_t i = 0; i < header.size(); i++) {
        if (header[i] == ',') {
            auto name = header.substr(prev, i-prev);
            r.fields.emplace_back(name, r.fields.size(), r.table);
            prev = i + 1;
        }
    }
    auto name = header.substr(prev, header.size()-prev);
    r.fields.emplace_back(name, r.fields.size(), r.table);

    std::sort(r.fields.begin(), r.fields.end());
    return r;
}

enum class OpCode { OPEN, KEY, READ, COMMA, CLOSE };

struct Op {
    OpCode    op;
    union {
        ptrdiff_t index;
        Token     token;
    };

    Op(OpCode op, ptrdiff_t index) : op{op}, index{index} {}
    Op(OpCode op, Token token) : op{op}, token{token} {}
};

inline std::vector<Op> compile(Headers const& headers)
{
    std::vector<Op> program = {};
    program.emplace_back(OpCode::OPEN, 0);

    ptrdiff_t i = 0;
    std::vector<Token> stack = {};

    for (auto& field : headers.fields) {
        auto& tokens = field.tokens;
        for (; stack.size()+1 > tokens.size(); stack.pop_back()) {
            program.emplace_back(OpCode::CLOSE, 0);
        }

        while (!stack.empty()) {
            if (stack.back() == tokens[stack.size()-1]) {
                break;
            }
            program.emplace_back(OpCode::CLOSE, 0);
            stack.pop_back();
        }

        if (i++ > 0) {
            program.emplace_back(OpCode::COMMA, 0);
        }

        while (stack.size() < tokens.size()-1) {
            Token token = tokens[stack.size()];
            stack.push_back(token);
            program.emplace_back(OpCode::KEY, token);
            program.emplace_back(OpCode::OPEN, 0);
        }

        program.emplace_back(OpCode::KEY, tokens.back());
        program.emplace_back(OpCode::READ, field.index);
    }

    for (; !stack.empty(); stack.pop_back()) {
        program.emplace_back(OpCode::CLOSE, 0);
    }
    program.emplace_back(OpCode::CLOSE, 0);
    return program;
}

inline void run(
    std::vector<Op> const& program,
    std::ostream& out,
    StrTable const& strtab,
    std::span<double> const record
)
{
    for (auto& op : program) {
        switch (op.op) {
        case OpCode::OPEN: {
            out << "{";
        } break;
        case OpCode::KEY: {
            out << '"' << strtab[op.token] << "\":";
        } break;
        case OpCode::READ: {
            std::array<char, 32> buf;
            double value = record[op.index];
            auto ptr = std::to_chars(
                buf.data(), buf.data()+buf.size(), value
            ).ptr;
            out << Str(buf.data(), ptr - buf.data());
        } break;
        case OpCode::COMMA: {
            out << ",";
        } break;
        case OpCode::CLOSE: {
            out << "}";
        } break;
        }
    }
    out << "\n";
}

// Test code

inline std::int32_t randint(std::uint64_t *s, std::int32_t lo, std::int32_t hi)
{
    *s = *s*0x3243f6a8885a308d + 1;
    auto range = static_cast<std::uint64_t>(hi - lo);
    return static_cast<std::int32_t>(((*s>>32)*range)>>32) + lo;
}

inline std::string generate_field(std::uint64_t *rng)
{
    static const char words[64][8] = {
        "entry", "debtor", "better", "threw", "earl", "car", "tray", "grip",
        "plane", "hair", "feeder", "field", "maple", "thirty", "picked",
        "grey", "not", "lifted", "miner", "idea", "glance", "throw", "dumped",
        "pepper", "keep", "recipe", "extra", "hoop", "owe", "throat", "roe",
        "ounce", "mirage", "hereby", "coded", "rib", "atomic", "funded",
        "yacht", "affair", "coop", "length", "fatal", "hack", "jam", "wave",
        "hitch", "native", "long", "tattoo", "many", "enroll", "clergy",
        "tab", "ended", "fun", "bound", "windy", "incur", "forty", "pound",
        "upward", "cavity", "mad",
    };
    std::int32_t len = randint(rng, 1, 7);
    std::string r;
    for (std::int32_t i = 0; i < len; i++) {
        if (i) {
            r += ".";
        }
        r += words[randint(rng, 0, std::ssize(words))];
    }
    return r;
}

inline std::string generate_header(std::uint64_t *rng)
{
    std::int32_t len = randint(rng, 10, 100);
    std::string r;
    for (std::int32_t i = 0; i < len; i++) {
        if (i) {
            r += ",";
        }
        r += generate_field(rng);
    }
    return r;
}

int main()
{
    // Visual test/debugging
    auto headers = parse_header(
        "label,"
        "point.x,"
        "point.y,"
        "foo.bar.baz,"
        "point.z"
    );
    auto program = compile(headers);
    double record[] = {
        12345,
        1.23,
        4.56,
        3.141592653589793,
        7.89,
    };
    run(program, std::cout, headers.table, record);

    // Benchmark
    std::uint64_t rng = 1;
    for (int i = 0; i < 10000; i++) {
        auto s = generate_header(&rng);
        auto headers = parse_header(s);
        auto program = compile(headers);
        #if 0
        std::vector<double> v(headers.fields.size());
        run(program, std::cout, headers.table, v);
        #endif
    }

    return 0;
}
