#include "eval.hh"
#include "bytecode.hh"
#include "nixexpr.hh"
#include <functional>
namespace nix {

std::string showAttrPath(const SymbolTable & symbols, const AttrPath & attrPath);
class ThunkIdx {
public:
    uint32_t idx;
};
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
struct pushWith {
    static const byteCodeT type = bWith;
    PosIdx pos;
    uint16_t prevWith;
    std::ostream& repr(std::ostream& out) {
        return out << "pushWith " << prevWith;
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
    ThunkIdx ix;
    std::ostream& repr(std::ostream& out) {return out << "thunk " << ix.idx;};
};
struct jmp {
    static const byteCodeT type = bJmp;
    int32_t ip;
    std::ostream& repr(std::ostream& out) {return out << "jmp " << ip;};
};

struct jmpNot {
    static const byteCodeT type = bJmpNot;
    PosIdx pos;
    int32_t ip;
    std::ostream& repr(std::ostream& out) {return out << "jmpnot " << ip;};
};
struct call {
    static const byteCodeT type = bCall;
    PosIdx pos;
    uint8_t arity;
    std::ostream& repr(std::ostream& out) {return out << "call " << (uint32_t)arity;};
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
struct assert {
    static const byteCodeT type = bAssert;
    PosIdx pos;
    std::ostream& repr(std::ostream& out) {return out << "assert";};
};
struct attrs {
    static const byteCodeT type = bAttrs;
    PosIdx pos;
    uint32_t count;
    std::ostream& repr(std::ostream& out) {return out << "attrs " << count;};
};
struct dup {
    static const byteCodeT type = bDup;
    std::ostream& repr(std::ostream& out) {return out << "dup";};
};
struct lambda {
    static const byteCodeT type = bLambda;
    PosIdx pos;
    Symbol name;
    Symbol arg;
    ThunkIdx body;
    std::ostream& repr(std::ostream& out, SymbolTable& st, ByteCodeChunk& c) {
        return out << "lambda " << st[arg] << " " << body.idx;
    };
};
struct let {
    static const byteCodeT type = bLet;
    std::ostream& repr(std::ostream& out) {return out << "let";};
};
struct letEnd {
    static const byteCodeT type = bLetEnd;
    std::ostream& repr(std::ostream& out) {return out << "letend";};
};
struct concatStrings {
    static const byteCodeT type = bConcatStr;
    PosIdx pos;
    bool forceString;
    uint32_t count;
    // PosIdx positions[]; // TODO
    std::ostream& repr(std::ostream& out) {return out << "concatstrings " << count;};
};
#pragma pack(pop)
};

class ByteCodeChunkIterator {
private:
    template<class T> void set(T t) {
        *(T*)(&c.code.data()[ip]) = t;
    };
public:
    ByteCodeChunk& c;
    unsigned int ip;
    ByteCodeChunkIterator(ByteCodeChunk& c, unsigned int ip=0) : c(c), ip(ip) { };
    template<class T> T get() {
        T t = *(T*)(&c.code.data()[ip]);
        ip += sizeof(T);
        return t;
    };
    template<class T> T peek() {
        return *(T*)(&c.code.data()[ip]);
    };
    template<class T> ByteCodeChunkIterator put(T t) {
        c.push(T::type);
        ip++;
        ByteCodeChunkIterator ret = *this;
        c.code.resize(ip + sizeof(T));
        *(T*)(&c.code.data()[ip]) = t;
        ip += sizeof(T);
        return ret;
    };
    [[nodiscard]] ThunkIdx addThunk(std::function<void(ByteCodeChunkIterator&)> thunk) {
        auto t = new ByteCodeChunk();
        ByteCodeChunkIterator it(*t);
        thunk(it);
        c.thunks.push_back(t);
        return ThunkIdx{(uint32_t)c.thunks.size() - 1};
        //put(opcode::thunk{(uint32_t)(c.thunks.size() - 1)});
    };
    void putThunk(std::function<void(ByteCodeChunkIterator&)> thunk) {
        put(opcode::thunk{addThunk(thunk)});
    };
    // todo: type safety would be nice
    template<class T> void setJmp(ByteCodeChunkIterator& where) {
        T jmpInstr = peek<T>();
        jmpInstr.ip = where.ip - ip;
        set(jmpInstr);
    };
    bool done() { return ip >= c.code.size(); };
};

void decompile(SymbolTable& st, ByteCodeChunk& c, std::ostream & str, std::string_view name, uint indent=0) {
    ByteCodeChunkIterator i(c);
    str << std::string(indent, ' ') << "chunk `" << name << "` {" << std::endl;
    indent += 2;
    size_t cnt = 0;
    for (auto& t : c.thunks) {
        decompile(st, *t, str, "thunk " + std::to_string(cnt++), indent);
    }
    while (!i.done()) {
        byteCodeT code = (byteCodeT)i.get<uint8_t>();
        str << std::string(indent, ' ');
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
            i.get<opcode::pushWith>().repr(str) << std::endl;
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
        case bAssert: i.get<opcode::assert>().repr(str) << std::endl; break;
        case bAttrs: i.get<opcode::attrs>().repr(str) << std::endl; break;
        case bDup: i.get<opcode::dup>().repr(str) << std::endl; break;
        case bLambda: i.get<opcode::lambda>().repr(str, st, c) << std::endl; break;
        case bLet: i.get<opcode::let>().repr(str) << std::endl; break;
        case bLetEnd: i.get<opcode::letEnd>().repr(str) << std::endl; break;
        case bConcatStr: i.get<opcode::concatStrings>().repr(str) << std::endl; break;
        default:
            assert(false);
            break;
        };
    }
    indent -= 2;
    str << std::string(indent, ' ') << "}" << std::endl;
}

void ExprLiteral::compile(ByteCodeChunkIterator & c) const {
    c.put(opcode::loadconst{c.c.addConstant(v)});
};

void ExprVar::compile(ByteCodeChunkIterator& c) const {
    // todo - check if this is a local variable
    c.putThunk([this](ByteCodeChunkIterator& c) {
        if (this->fromWith) {
            c.put(opcode::loadwith{pos, name, level});
        } else {
            c.put(opcode::loadvar{pos, name, level, displ});
        }
    });
};
void ExprSelect::compile(ByteCodeChunkIterator& c) const {
    e->compile(c);
    assert(!def); // TODO
    // if (def) {
    //     c.push(bDup);
    //     c.push(bHasAttr);
    //     c.push(attrPath);
    //     c.push(bNot);
    //     c.push(bJmpNot);
    //     pushPos(c, noPos);
    //     uint32_t afterIx = c.code.size();
    //     c.push((uint32_t)0);
    //     def->compile(c);
    //     c.push(bJmp);
    //     c.push((uint32_t)(c.code.size() + 9));
    //     c.set(afterIx, c.code.size());
    // }
    c.put(opcode::select{pos, c.c.addAttrPath(attrPath)});
};
void ExprOpHasAttr::compile(ByteCodeChunkIterator& c) const {
    e->compile(c);
    c.put(opcode::hasAttr{c.c.addAttrPath(attrPath)});
};
void ExprAttrs::compile(ByteCodeChunkIterator& c) const {
    uint32_t cnt = 0;
    if (recursive) {
        // todo
        assert(false);
    } else {
        for (auto & i : attrs) {
            // c.push(*reinterpret_cast<const uint32_t*>(&i.first));
            // // todo thunk
            // i.second.e->compile(c);
            cnt++;
        }
        for (auto & i : dynamicAttrs) {
            // todo
            cnt++;
        }
    }
    c.put(opcode::attrs{pos, cnt});
};
void ExprList::compile(ByteCodeChunkIterator& c) const {
    uint32_t cnt = 0;
    for (auto i : elems) {
        // todo: maybe thunk
        c.putThunk([&](auto& c) {
            i->compile(c);
        });
        cnt++;
    }
    c.put(opcode::list{cnt});
};
void ExprLambda::compile(ByteCodeChunkIterator& c) const {
    // TODO formals
    assert(!hasFormals());
    ThunkIdx idx = c.addThunk([&](auto& c) {
        body->compile(c);
    });
    c.put(opcode::lambda{pos, name, arg, idx});

};
void ExprCall::compile(ByteCodeChunkIterator& c) const {
    size_t cnt = 0;
    for (auto &i : args) {
        // todo: maybe thunk
        c.putThunk([&](auto& c) {
            i->compile(c);
        });
        cnt++;
    }
    assert(cnt < 256);
    fun->compile(c);
    c.put(opcode::call{pos, (uint8_t)cnt});
};
void ExprLet::compile(ByteCodeChunkIterator&c) const {
    attrs->compile(c);
    c.put(opcode::let{});
    body->compile(c);
    c.put(opcode::letEnd{});

};
void ExprWith::compile(ByteCodeChunkIterator&c) const {
    attrs->compile(c);
    c.put(opcode::pushWith{pos, (uint16_t)prevWith});
    body->compile(c);
    c.put(opcode::popWith{});

};
void ExprIf::compile(ByteCodeChunkIterator&c) const {
    cond->compile(c);
    ByteCodeChunkIterator elseJmp = c.put(opcode::jmpNot{pos});
    then->compile(c);
    ByteCodeChunkIterator endJmp = c.put(opcode::jmp{});
    elseJmp.setJmp<opcode::jmpNot>(c);
    else_->compile(c);
    endJmp.setJmp<opcode::jmp>(c);
};
void ExprAssert::compile(ByteCodeChunkIterator&c) const {
    cond->compile(c);
    c.put(opcode::assert{pos});
    body->compile(c);
};
void ExprOpNot::compile(ByteCodeChunkIterator&c) const {
    e->compile(c);
    c.put(opcode::not_{});
};

void ExprOpEq::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpEq>{pos});
};
void ExprOpNEq::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpNEq>{pos});
};
void ExprOpAnd::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpAnd>{pos});
};
void ExprOpOr::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpOr>{pos});
};
void ExprOpImpl::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpImpl>{pos});
};
void ExprOpUpdate::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpUpdate>{pos});
};
void ExprOpConcatLists::compile(ByteCodeChunkIterator&c) const {
    e1->compile(c);
    e2->compile(c);
    c.put(opcode::binop<bOpConcatList>{pos});
};

void ExprConcatStrings::compile(ByteCodeChunkIterator&c) const {
    for (auto & i : *es) {
        i.second->compile(c);
    }
    // todo: save positions somewhere
    c.put(opcode::concatStrings{pos, forceString, (uint32_t)es->size()});
};
void ExprPos::compile(ByteCodeChunkIterator& c) const {
    c.put(opcode::pos{pos});
};

void decompileExpr(Expr* e, SymbolTable& st, std::ostream& str) {
    ByteCodeChunk toplevel;
    ByteCodeChunkIterator c(toplevel);
    e->compile(c);
    decompile(st, toplevel, str, "toplevel", 0);
}
}
