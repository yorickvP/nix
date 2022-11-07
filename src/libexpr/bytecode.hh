#pragma once

#include <cassert>

#include "value.hh"
#include "nixexpr.hh"

#if HAVE_BOEHMGC
#include <gc/gc_allocator.h>
#endif

namespace nix {
enum byteCodeT {
    bLoadConst = 1, // u32 ix: Value& consts[ix] // +1
    bLoadVar, // u32 pos, symbol name, bool fromWith, u32 level, u32 displ // +1
    bSelect, // u32 pos, attrpath, expr default // -1+1
    bHasAttr, // attrpath // -1+1
    bAttrs,
    bList, // uint32 length, // -n+1
    bLambda, // u32 pos, name, arg, formals, body
    bCall, // u32 pos, pop(1)(pop(nArgs))
    bLet, // expr1, expr2 // +1
    bWith, // u32 pos, expr body, u32 prevWith // -1+1
    bIf, // u32 pos, expr else // -1+1
    bAssert, // u32 pos, expr body // -1+1
    bNot, // -1+1
    bOpEq, // -2+1
    bOpNEq, // -2+1
    bOpAnd, // -2+1
    bOpOr, // -2+1
    bOpImpl, // -2+1
    bOpUpdate, // -2+1
    bOpConcatList, // -2+1
    bConcatStr, // u32 pos, b force, u32 nargs
    bPos, // u32 pos
    bPopEnv,
    bJmp, // u32 target
    bDup,
};

struct ByteCodeChunk {
    std::vector<uint8_t> code;
    std::vector<const Value*> consts;
    std::vector<const AttrPath*> attrPaths;
    ByteCodeChunk() = default;
    ByteCodeChunk(ByteCodeChunk &&) = delete;
    ByteCodeChunk &operator=(ByteCodeChunk &&) = delete;
    void push(byteCodeT op) {
        code.push_back(op);
    };
    void push(uint8_t op) {
        code.push_back(op);
    };
    void set(uint32_t ix, uint32_t val) {
        assert(ix < code.size());
        assert(code[ix] == 0);
        code[ix] = val & 0xff;
        code[ix + 1] = (val >> 8) & 0xff;
        code[ix + 2] = (val >> 16) & 0xff;
        code[ix + 3] = (val >> 24) & 0xff;
    };
    void push(uint32_t x) {
        code.push_back(x & 0xff);
        code.push_back((x >> 8) & 0xff);
        code.push_back((x >> 16) & 0xff);
        code.push_back((x >> 24) & 0xff);
    };
    void push(uint16_t x) {
        code.push_back(x & 0xff);
        code.push_back((x >> 8) & 0xff);
    };
    void push(const Value &v) {
        consts.push_back(&v);
        push((uint32_t)(consts.size() - 1));
    };
    void push(const AttrPath &p) {
        attrPaths.push_back(&p);
        push((uint32_t)(attrPaths.size() - 1));
    };
    void push(bool x) { code.push_back(x); };
    uint32_t get_u32(uint32_t ix) {
        assert(ix < code.size());
        return code[ix] | (code[ix + 1] << 8) | (code[ix + 2] << 16) | (code[ix + 3] << 24);
    };
    const Value *get_val(uint32_t ix) {
        return consts[get_u32(ix)];
    };
    const AttrPath *get_attrPath(uint32_t ix) {
        return attrPaths[get_u32(ix)];
    };
};
}

