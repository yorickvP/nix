#include "eval.hh"
#include "bytecode.hh"
#include "nixexpr.hh"
#include <functional>
#include <stack>
namespace nix {

struct ByteCodeChunk {
    std::vector<uint8_t> code;
    std::vector<const Value*> consts;
    std::vector<const AttrPath*> attrPaths;
    std::vector<ByteCodeChunk*> thunks;
    ByteCodeChunk() = default;
    ByteCodeChunk(ByteCodeChunk &&) = delete;
    ByteCodeChunk &operator=(ByteCodeChunk &&) = delete;
    uint32_t addConstant(const Value &v) {
        consts.push_back(&v);
        return consts.size() - 1;
    };
    uint32_t addAttrPath(const AttrPath &p) {
        attrPaths.push_back(&p);
        return attrPaths.size() - 1;
    };
};
enum byteCodeT {
    bLoadConst = 1, // u32 ix: Value& consts[ix] // +1
    bLoadVar, // u32 pos, symbol name, u32 level, u32 displ // +1
    bLoadWith, // u32 pos, symbol name, u32 level // +1
    bSelect, // u32 pos, attrpath, expr default // -1+1
    bHasAttr, // attrpath // -1+1
    bAttrs,
    bList, // uint32 length, // -n+1
    bLambda, // u32 pos, name, arg, formals, body
    bCall, // u32 pos, pop(1)(pop(nArgs))
    bLet, // -1
    bLetEnd, // 0
    bWith, // u32 pos, u32 prevWith // -1+1
    bJmpNot, // u32 pos, expr else // -1+1
    bAssert, // u32 pos // -1+1
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
    bPopWith,
    bJmp, // u32 target
    bDup,
    bThunk, // u32 thunkNr
};
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
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        out << "loadconst ";
        c.consts[index]->print(st, out);
        return out;
    };
};
struct list {
    static const byteCodeT type = bList;
    uint32_t size;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "list " << size;
    };
};
struct loadvar {
    static const byteCodeT type = bLoadVar;
    PosIdx pos;
    Symbol name;
    uint32_t level;
    uint32_t displacement;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "loadvar " << st[name] << " " << level << " " << displacement;
    };
};
struct loadwith {
    static const byteCodeT type = bLoadWith;
    PosIdx pos;
    Symbol name;
    uint32_t level;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "loadwith " << st[name] << " " << level;
    };
};
struct pushWith {
    static const byteCodeT type = bWith;
    PosIdx pos;
    uint16_t prevWith;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "pushWith " << prevWith;
    };
};
template<byteCodeT op> struct binop {
    static const byteCodeT type = op;
    PosIdx pos;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
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
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "pos";};
};
struct thunk {
    static const byteCodeT type = bThunk;
    ThunkIdx ix;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "thunk " << ix.idx;};
};
struct jmp {
    static const byteCodeT type = bJmp;
    int32_t ip;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "jmp " << ip;};
};

struct jmpNot {
    static const byteCodeT type = bJmpNot;
    PosIdx pos;
    int32_t ip;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "jmpnot " << ip;};
};
struct call {
    static const byteCodeT type = bCall;
    PosIdx pos;
    uint8_t arity;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "call " << (uint32_t)arity;};
};
struct not_ {
    static const byteCodeT type = bNot;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "not";};
};
struct popWith {
    static const byteCodeT type = bPopWith;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "popwith";};
};
struct hasAttr {
    static const byteCodeT type = bHasAttr;
    uint32_t attr;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "hasattr " << showAttrPath(st, *c.attrPaths[attr]);
    };
};
struct select {
    static const byteCodeT type = bSelect;
    PosIdx pos;
    uint32_t attr;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "select " << showAttrPath(st, *c.attrPaths[attr]);
    };
};
struct assert {
    static const byteCodeT type = bAssert;
    PosIdx pos;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "assert";};
};
struct attrs {
    static const byteCodeT type = bAttrs;
    PosIdx pos;
    uint32_t count;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "attrs " << count;};
};
struct dup {
    static const byteCodeT type = bDup;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "dup";};
};
struct lambda {
    static const byteCodeT type = bLambda;
    PosIdx pos;
    Symbol name;
    Symbol arg;
    ThunkIdx body;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "lambda " << st[arg] << " " << body.idx;
    };
};
struct let {
    static const byteCodeT type = bLet;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "let";};
};
struct letEnd {
    static const byteCodeT type = bLetEnd;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "letend";};
};
struct concatStrings {
    static const byteCodeT type = bConcatStr;
    PosIdx pos;
    bool forceString;
    uint32_t count;
    // PosIdx positions[]; // TODO
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "concatstrings " << count;};
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
        c.code.push_back(T::type);
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

template<class Visitor>
void decode(ByteCodeChunk& c, Visitor v) {
    ByteCodeChunkIterator i(c);
    while (!i.done()) {
        byteCodeT code = (byteCodeT)i.get<uint8_t>();
        switch(code) {
        case bLoadConst: v(i.get<opcode::loadconst>()); break;
        case bList: v(i.get<opcode::list>()); break;
        case bLoadVar: v(i.get<opcode::loadvar>()); break;
        case bLoadWith: v(i.get<opcode::loadwith>()); break;
        case bNot: v(i.get<opcode::not_>()); break;
        case bWith: v(i.get<opcode::pushWith>()); break;
        case bPopWith: v(i.get<opcode::popWith>()); break;
        case bJmp: v(i.get<opcode::jmp>()); break;
        case bJmpNot: v(i.get<opcode::jmpNot>()); break;
        case bOpEq: v(i.get<opcode::binop<bOpEq>>()); break;
        case bOpNEq: v(i.get<opcode::binop<bOpNEq>>()); break;
        case bOpAnd: v(i.get<opcode::binop<bOpAnd>>()); break;
        case bOpOr: v(i.get<opcode::binop<bOpOr>>()); break;
        case bOpImpl: v(i.get<opcode::binop<bOpImpl>>()); break;
        case bOpUpdate: v(i.get<opcode::binop<bOpUpdate>>()); break;
        case bOpConcatList: v(i.get<opcode::binop<bOpConcatList>>()); break;
        case bPos: v(i.get<opcode::pos>()); break;
        case bCall: v(i.get<opcode::call>()); break;
        case bHasAttr: v(i.get<opcode::hasAttr>()); break;
        case bSelect: v(i.get<opcode::select>()); break;
        case bThunk: v(i.get<opcode::thunk>()); break;
        case bAssert: v(i.get<opcode::assert>()); break;
        case bAttrs: v(i.get<opcode::attrs>()); break;
        case bDup: v(i.get<opcode::dup>()); break;
        case bLambda: v(i.get<opcode::lambda>()); break;
        case bLet: v(i.get<opcode::let>()); break;
        case bLetEnd: v(i.get<opcode::letEnd>()); break;
        case bConcatStr: v(i.get<opcode::concatStrings>()); break;
        default:
            assert(false);
            break;
        };
    }
}
template <class... Ts> struct match : Ts... { using Ts::operator()...; };
template <class... Ts> match(Ts...)->match<Ts...>;

void decompile(const SymbolTable& st, ByteCodeChunk& c, std::ostream & str, std::string_view name, uint indent=0) {
    ByteCodeChunkIterator i(c);
    str << std::string(indent, ' ') << name << " {" << std::endl;
    indent += 2;
    size_t cnt = 0;
    for (auto& t : c.thunks) {
        decompile(st, *t, str, "thunk " + std::to_string(cnt++), indent);
    }
    decode(c, [&](auto t) {
        str << std::string(indent, ' ');
        t.repr(str, st, c) << std::endl;
    });
    indent -= 2;
    str << std::string(indent, ' ') << "}" << std::endl;
}

static void eval(ByteCodeChunk& c, EvalState & state, Env & env, Value & v);
struct ExprCompiled : Expr {
    ByteCodeChunk& c;
    ExprCompiled(ByteCodeChunk& c) : c(c) {}
    void compile(ByteCodeChunkIterator& c) const override {
        assert(false);
    }
    void show(const SymbolTable & symbols, std::ostream & str) const override {
        decompile(symbols, c, str, "toplevel", 0);
    };
    void eval(EvalState & state, Env & env, Value & v) override {
        nix::eval(c, state, env, v);
    };
    void bindVars(EvalState & es, const std::shared_ptr<const StaticEnv> & env) override {};
};

Expr* compileExpr(Expr* e) {
    ByteCodeChunk* toplevel = new ByteCodeChunk();
    ByteCodeChunkIterator c(*toplevel);
    e->compile(c);
    return new ExprCompiled(*toplevel);
}
static void eval(ByteCodeChunk& c, EvalState & state, Env & env, Value & v) {
    ByteCodeChunkIterator i(c);
    std::stack<Value*> stack;
    decode(c, match {
        [&stack, &c](opcode::loadconst op) {
            stack.push(const_cast<Value*>(c.consts[op.index]));
        },
        [&state, &stack](opcode::list op) {
            Value* v = state.allocValue();
            state.mkList(*v, op.size);
            for (size_t i = 0; i < op.size; i++) {
                v->listElems()[op.size - i - 1] = stack.top();
                stack.pop();
            }
            stack.push(v);
        },
        [&env, &stack](opcode::loadvar op) {
            Env *e = &env;
            for (auto l = op.level; l; --l, e = e->up) ;
            stack.push(e->values[op.displacement]);
        },
        [&state, &stack, &env](opcode::loadwith op) {
            ExprVar var(op.pos, op.name);
            var.fromWith = true;
            var.level = op.level;
            stack.push(state.lookupVarWith(&env, var, false));
        },
        [&state, &stack](opcode::not_ op) {
            bool b = state.forceBool(*stack.top(), noPos);
            stack.top()->boolean = !b;
        },
        [&env, &stack, &state](opcode::pushWith op) {
            Env & env2(state.allocEnv(1));
            env2.up = &env;
            env2.prevWith = op.prevWith;
            env2.hasWith = true;
            env2.values[0] = stack.top();
            stack.pop();
            env = env2;
        },
        [&env](opcode::popWith op) {
            env = *env.up;
        },
        // opcode::jmp
        // opcode::jmpNot
        [&stack, &state](opcode::binop<bOpEq> op) {
            Value* v1 = stack.top(); stack.pop();
            Value* v2 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            stack.top()->mkBool(state.eqValues(*v1, *v2));
        },
        [&stack, &state](opcode::binop<bOpNEq> op) {
            Value* v1 = stack.top(); stack.pop();
            Value* v2 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            stack.top()->mkBool(!state.eqValues(*v1, *v2));
        },
        [&stack, &state](opcode::binop<bOpAnd> op) {
            Value* v1 = stack.top(); stack.pop();
            Value* v2 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            stack.top()->mkBool(state.forceBool(*v1, op.pos) && state.forceBool(*v2, op.pos));
        },
        [&stack, &state](opcode::binop<bOpOr> op) {
            Value* v1 = stack.top(); stack.pop();
            Value* v2 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            stack.top()->mkBool(state.forceBool(*v1, op.pos) || state.forceBool(*v2, op.pos));
        },
        [&stack, &state](opcode::binop<bOpImpl> op) {
            // reverse
            Value* v2 = stack.top(); stack.pop();
            Value* v1 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            stack.top()->mkBool(!state.forceBool(*v1, op.pos) || state.forceBool(*v2, op.pos));
        },
        // opcode::binop<bOpUpdate>
        [&stack, &state](opcode::binop<bOpConcatList> op) {
            Value* v2 = stack.top(); stack.pop();
            Value* v1 = stack.top(); stack.pop();
            stack.push(state.allocValue());
            Value * lists[2] = { v1, v2 };
            state.concatLists(*stack.top(), 2, lists, op.pos);
        },
        [&stack, &state](opcode::pos op) {
            stack.push(state.allocValue());
            state.mkPos(*stack.top(), op.pos);
        },
        [&stack, &state](opcode::call op) {
            Value* fun = stack.top(); stack.pop();
            Value * vArgs[op.arity];
            for (size_t i = 0; i < op.arity; i++) {
                vArgs[op.arity - i - 1] = stack.top();
                stack.pop();
            }
            stack.push(state.allocValue());
            state.callFunction(*fun, op.arity, vArgs, *stack.top(), op.pos);
        },
        // opcode::hasAttr
        // opcode::select
        [&c, &stack, &env, &state](opcode::thunk op) {
            Value* v = state.allocValue();
            Expr *e = new ExprCompiled(*c.thunks[op.ix.idx]);
            v->mkThunk(&env, e);
            stack.push(v);
        },
        [&](opcode::assert op) {
            Value* v = stack.top(); stack.pop();
            bool b = state.forceBool(*v, op.pos);
            if (!b) {
                // todo: debug repl
                throw AssertionError({
                        .msg = hintfmt("assertion '?' failed"),
                        .errPos = state.positions[op.pos]
                    });
            }
        },
        // opcode::attrs
        [&stack](opcode::dup op) {
            stack.push(stack.top());
        },
        [&stack, &c, &state, &env](opcode::lambda op) {
            // todo: formals
            Expr *compiled = new ExprCompiled(*c.thunks[op.body.idx]);
            ExprLambda *l = new ExprLambda(op.pos, op.arg, nullptr, compiled);
            l->setName(op.name);
            stack.push(state.allocValue());
            stack.top()->mkLambda(&env, l);
        },
        // opcode::let
        // opcode::letEnd
        // opcode::concatStrings
        [&](auto t) {
            assert(false);
        }
    });
    v = *stack.top();
}

void ExprLiteral::compile(ByteCodeChunkIterator & c) const {
    c.put(opcode::loadconst{c.c.addConstant(v)});
};

void ExprVar::compile(ByteCodeChunkIterator& c) const {
    // todo: when is this thunk neccesary?
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
static void bmaybeThunk(ByteCodeChunkIterator& c, const Expr* e) {
    if (dynamic_cast<const ExprLiteral*>(e) != nullptr ||
        dynamic_cast<const ExprVar*>(e) != nullptr) {
        e->compile(c);
    } else {
        c.putThunk([e](ByteCodeChunkIterator& c) {
            e->compile(c);
        });
    }
}
void ExprList::compile(ByteCodeChunkIterator& c) const {
    uint32_t cnt = 0;
    for (auto i : elems) {
        // todo: maybe thunk
        bmaybeThunk(c, i);
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
        bmaybeThunk(c, i);
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
    bmaybeThunk(c, attrs);
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

void decompileExpr(Expr* e, const SymbolTable& st, std::ostream& str) {
    ByteCodeChunk toplevel;
    ByteCodeChunkIterator c(toplevel);
    e->compile(c);
    decompile(st, toplevel, str, "toplevel", 0);
}



}
