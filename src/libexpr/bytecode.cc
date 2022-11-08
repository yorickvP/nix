#include "eval.hh"
#include "bytecode.hh"
#include "nixexpr.hh"
namespace nix {

class ByteCodeChunk::Iterator {
    ByteCodeChunk& c;
    unsigned int ip;
public:
    Iterator(ByteCodeChunk& c, unsigned int ip=0) : c(c), ip(ip) { };
    template<class T> T get() {
        T t = *(T*)(&c.code.data()[ip]);
        ip += sizeof(T);
        return t;
    };
    template<class T> void set(T t) {
        *(T*)(&c.code.data()[ip]) = t;
        ip += sizeof(T);
    };
    template<class T> Iterator put(T t) {
        c.push(T::type);
        ip++;
        Iterator ret = *this;
        c.code.resize(ip + sizeof(T));
        *(T*)(&c.code.data()[ip]) = t;
        ip += sizeof(T);
        return ret;
    };
    bool done() { return ip >= c.code.size(); };
};

// enum byteCodeT {
//     bAttrs,
//     bLambda, // u32 pos, name, arg, formals, body
//     bLet, // expr1, expr2 // +1
//     bAssert, // u32 pos, expr body // -1+1
//     bConcatStr, // u32 pos, b force, u32 nargs
//     bDup,
// };

std::string showAttrPath(const SymbolTable & symbols, const AttrPath & attrPath);
namespace opcode {
#pragma pack(push, 1)
struct loadconst {
    static const byteCodeT type = bLoadConst;
    uint32_t index;
    std::ostream& repr(std::ostream& out, SymbolTable& st, ByteCodeChunk& c) {
        out << "loadconst ";
        c.consts[index]->print(st, out);
        return out;
    };
};
struct list {
    static const byteCodeT type = bList;
    uint32_t size;
    std::ostream& repr(std::ostream& out) {return out << "list " << size;};
};
struct loadvar {
    static const byteCodeT type = bLoadVar;
    PosIdx pos;
    Symbol name;
    uint32_t level;
    uint32_t displacement;
    std::ostream& repr(std::ostream& out, SymbolTable& st) {
        return out << "loadvar " << st[name] << " " << level << " " << displacement;
    };
};
struct loadwith {
    static const byteCodeT type = bLoadWith;
    PosIdx pos;
    Symbol name;
    uint32_t level;
    std::ostream& repr(std::ostream& out, SymbolTable& st) {
        return out << "loadwith " << st[name] << " " << level;
    };
};
struct pushwith {
    static const byteCodeT type = bWith;
    PosIdx pos;
    uint16_t prevWith;
    std::ostream& repr(std::ostream& out) {
        return out << "pushwith " << prevWith;
    };
};
template<byteCodeT op> struct binop {
    static const byteCodeT type = op;
    PosIdx pos;
    std::ostream& repr(std::ostream& out) {
        switch (op) {
            case bOpEq: return out << "eq";
            case bOpNEq: return out << "neq";
            case bOpAnd: return out << "and";
            case bOpOr: return out << "or";
            case bOpImpl: return out << "impl";
            case bOpUpdate: return out << "update";
            case bOpConcatList: return out << "concatlist";
            default: return out << "binop?? " << op;
        };
    };
};
struct pos {
    static const byteCodeT type = bPos;
    PosIdx pos;
    std::ostream& repr(std::ostream& out) {return out << "pos";};
};
struct thunk {
    static const byteCodeT type = bThunk;
    uint32_t ix;
    std::ostream& repr(std::ostream& out) {return out << "thunk " << ix;};
};
struct jmp {
    static const byteCodeT type = bJmp;
    uint32_t ip;
    std::ostream& repr(std::ostream& out) {return out << "jmp " << ip;};
};

struct jmpNot {
    static const byteCodeT type = bJmpNot;
    PosIdx pos;
    uint32_t ip;
    std::ostream& repr(std::ostream& out) {return out << "jmpnot " << ip;};
};
struct call {
    static const byteCodeT type = bCall;
    PosIdx pos;
    uint8_t arity;
    std::ostream& repr(std::ostream& out) {return out << "call " << arity;};
};
struct not_ {
    static const byteCodeT type = bNot;
    std::ostream& repr(std::ostream& out) {return out << "not";};
};
struct popWith {
    static const byteCodeT type = bPopWith;
    std::ostream& repr(std::ostream& out) {return out << "popwith";};
};
struct hasAttr {
    static const byteCodeT type = bHasAttr;
    uint32_t attr;
    std::ostream& repr(std::ostream& out, SymbolTable& st, ByteCodeChunk& c) {
        return out << "hasattr " << showAttrPath(st, *c.attrPaths[attr]);
    };
};
struct select {
    static const byteCodeT type = bSelect;
    PosIdx pos;
    uint32_t attr;
    std::ostream& repr(std::ostream& out, SymbolTable& st, ByteCodeChunk& c) {
        return out << "select " << showAttrPath(st, *c.attrPaths[attr]);
    };
};
#pragma pack(pop)
};

void decompile(SymbolTable& st, ByteCodeChunk& c, uint32_t ix, std::ostream & str) {
    ByteCodeChunk::Iterator i(c, ix);
    while (!i.done()) {
        byteCodeT code = (byteCodeT)i.get<uint8_t>();
        switch(code) {
        case bLoadConst:
            i.get<opcode::loadconst>().repr(str, st, c) << std::endl;
            break;
        case bList:
            i.get<opcode::list>().repr(str) << std::endl;
            break;
        case bLoadVar: {
            i.get<opcode::loadvar>().repr(str, st) << std::endl;
        }; break;
        case bLoadWith: {
            i.get<opcode::loadwith>().repr(str, st) << std::endl;
        }; break;
        case bNot:
            i.get<opcode::not_>().repr(str) << std::endl;
            break;
        case bWith:
            i.get<opcode::pushwith>().repr(str) << std::endl;
            break;
        case bPopWith:
            i.get<opcode::popWith>().repr(str) << std::endl;
            break;
        case bJmp:
            i.get<opcode::jmp>().repr(str) << std::endl;
            break;
        case bJmpNot:
            i.get<opcode::jmpNot>().repr(str) << std::endl;
            break;
        case bOpEq: i.get<opcode::binop<bOpEq>>().repr(str) << std::endl; break;
        case bOpNEq: i.get<opcode::binop<bOpNEq>>().repr(str) << std::endl; break;
        case bOpAnd: i.get<opcode::binop<bOpAnd>>().repr(str) << std::endl; break;
        case bOpOr: i.get<opcode::binop<bOpOr>>().repr(str) << std::endl; break;
        case bOpImpl: i.get<opcode::binop<bOpImpl>>().repr(str) << std::endl; break;
        case bOpUpdate: i.get<opcode::binop<bOpUpdate>>().repr(str) << std::endl; break;
        case bOpConcatList: i.get<opcode::binop<bOpConcatList>>().repr(str) << std::endl; break;
        case bPos: i.get<opcode::pos>().repr(str) << std::endl; break;
        case bCall: i.get<opcode::call>().repr(str) << std::endl; break;
        case bHasAttr: i.get<opcode::hasAttr>().repr(str, st, c) << std::endl; break;
        case bSelect: i.get<opcode::select>().repr(str, st, c) << std::endl; break;
        case bThunk: i.get<opcode::thunk>().repr(str) << std::endl; break;
        default: abort();
        }
    }
}

void ExprLiteral::compile(ByteCodeChunk & c) const {
    c.push(bLoadConst);
    c.push(v);
};
void pushPos(ByteCodeChunk& c, const PosIdx& pos) {
    c.push(*reinterpret_cast<const uint32_t*>(&pos));
}

void ExprVar::compile(ByteCodeChunk & c) const {
    // todo - check if this is a local variable
    c.push(bThunk);
    ByteCodeChunk& d = c.pushThunk();
    d.push(bLoadVar);
    pushPos(d, pos);
    d.push(*reinterpret_cast<const uint32_t*>(&name));
    d.push(fromWith);
    d.push((uint32_t)level);
    d.push((uint32_t)displ);
};
void ExprSelect::compile(ByteCodeChunk & c) const {
    e->compile(c);
    if (def) {
        c.push(bDup);
        c.push(bHasAttr);
        c.push(attrPath);
        c.push(bNot);
        c.push(bJmpNot);
        pushPos(c, noPos);
        uint32_t afterIx = c.code.size();
        c.push((uint32_t)0);
        def->compile(c);
        c.push(bJmp);
        c.push((uint32_t)(c.code.size() + 9));
        c.set(afterIx, c.code.size());
    }
    c.push(bSelect);
    pushPos(c, pos);
    c.push(attrPath);
};
void ExprOpHasAttr::compile(ByteCodeChunk & c) const {
    e->compile(c);
    c.push(bHasAttr);
    c.push(attrPath);
};
void ExprAttrs::compile(ByteCodeChunk & c) const {
    c.push(bAttrs);
    pushPos(c, pos);
    if (recursive) {
        // todo
    } else {
        for (auto & i : attrs) {
            // c.push(*reinterpret_cast<const uint32_t*>(&i.first));
            // // todo thunk
            // i.second.e->compile(c);
        }
        for (auto & i : dynamicAttrs) {
            // todo
        }
    }
};
void ExprList::compile(ByteCodeChunk & c) const {
    uint32_t cnt = 0;
    for (auto i : elems) {
        // todo: maybe thunk
        c.push(bThunk);
        ByteCodeChunk& d = c.pushThunk();
        i->compile(d);
        cnt++;
    }
    c.push(bList);
    c.push(cnt);
};
void ExprLambda::compile(ByteCodeChunk & c) const {
    c.push(bLambda);
    pushPos(c, pos);

};
void ExprCall::compile(ByteCodeChunk & c) const {
    uint32_t cnt = 0;
    for (auto &i : args) {
        // todo: maybe thunk
        c.push(bThunk);
        ByteCodeChunk& d = c.pushThunk();
        i->compile(d);
        cnt++;
    }
    fun->compile(c);
    c.push(bCall);
    pushPos(c, pos);
    c.push((uint8_t)cnt);
};
void ExprLet::compile(ByteCodeChunk &c) const {
    c.push(bLet);

};
void ExprWith::compile(ByteCodeChunk &c) const {
    attrs->compile(c);
    c.push(bWith);
    pushPos(c, pos);
    c.push((uint16_t)prevWith);
    body->compile(c);
    c.push(bPopWith);

};
void ExprIf::compile(ByteCodeChunk &c) const {
    cond->compile(c);
    c.push(bJmpNot);
    pushPos(c, pos);
    uint32_t elsepos = c.code.size();
    c.push((uint32_t)0);
    then->compile(c);
    c.push(bJmp);
    uint32_t endpos = c.code.size();
    c.push((uint32_t)0);
    c.set(elsepos, c.code.size());
    else_->compile(c);
    c.set(endpos, c.code.size());
};
void ExprAssert::compile(ByteCodeChunk &c) const {
    c.push(bAssert);
    pushPos(c, pos);

};
void ExprOpNot::compile(ByteCodeChunk &c) const {
    e->compile(c);
    c.push(bNot);
};

void ExprOpEq::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpEq);
    pushPos(c, pos);
};
void ExprOpNEq::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpNEq);
    pushPos(c, pos);
};
void ExprOpAnd::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpAnd);
    pushPos(c, pos);
};
void ExprOpOr::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpOr);
    pushPos(c, pos);
};
void ExprOpImpl::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpImpl);
    pushPos(c, pos);
};
void ExprOpUpdate::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpUpdate);
    pushPos(c, pos);
};
void ExprOpConcatLists::compile(ByteCodeChunk &c) const {
    e1->compile(c);
    e2->compile(c);
    c.push(bOpConcatList);
    pushPos(c, pos);
};

void ExprConcatStrings::compile(ByteCodeChunk &c) const {

};
void ExprPos::compile(ByteCodeChunk & c) const {
    c.push(bPos);
    pushPos(c, pos);
};
ByteCodeChunk& newByteCode() {
    return *new ByteCodeChunk();
};
void decompileExpr(Expr* e, SymbolTable& st, std::ostream& str) {
    ByteCodeChunk toplevel;
    e->compile(toplevel);
    decompile(st, toplevel, 0, str);
}
}
