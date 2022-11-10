#include "attr-set.hh"
#include "eval.hh"
#include "bytecode.hh"
#include "nixexpr.hh"
#include <functional>
#include <stack>
#include <iomanip>

namespace nix {

struct ByteCodeChunk {
    std::vector<uint8_t> code;
    std::vector<const Value*> consts;
    std::vector<ByteCodeChunk*> thunks;
    ByteCodeChunk() = default;
    ByteCodeChunk(ByteCodeChunk &&) = delete;
    ByteCodeChunk &operator=(ByteCodeChunk &&) = delete;
    uint32_t addConstant(const Value &v) {
        consts.push_back(&v);
        return consts.size() - 1;
    };
};
enum byteCodeT {
    bLoadConst = 1,
    bLoadSymbol,
    bLoadVar, bLoadWith, bSelect,
    bHasAttr, bAttrs, bList, bLambda,
    bReserveEnv,
    bCall, bLet, bCloseEnv, bPushWith,
    bJmpz, bAssert, bNot, bOpEq,
    bOpNEq, bOpAnd, bOpOr, bOpImpl,
    bOpUpdate, bOpConcatList, bConcatStr, bPos,
    bJmp, bDup, bThunk,
};
std::string showAttrPath(const SymbolTable & symbols, const AttrPath & attrPath);
std::optional<Value*> getAttrByPath(EvalState & state, Value* vAttrs, Env & env, const AttrPath & attrPath, PosIdx pos, std::function<std::optional<Value*>(Value*, Symbol)> notFound, PosIdx& pos2);
struct ThunkIdx { uint32_t idx; };

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
struct loadsymbol {
    static const byteCodeT type = bLoadSymbol;
    Symbol s;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        out << "loadsymbol ";
        out << st[s];
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
    static const byteCodeT type = bPushWith;
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

struct jmpz {
    static const byteCodeT type = bJmpz;
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
struct hasAttr {
    static const byteCodeT type = bHasAttr;
    uint32_t attrPathLen;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "hasattr " << attrPathLen;
    };
};
struct select {
    static const byteCodeT type = bSelect;
    PosIdx pos;
    uint32_t attrPathLen;
    int32_t ip;
    std::ostream& repr(std::ostream& out, const SymbolTable& st, ByteCodeChunk& c) {
        return out << "select " << attrPathLen << " " << ip;
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
    uint32_t recursive;
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
struct reserveEnv {
    static const byteCodeT type = bReserveEnv;
    uint32_t size;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "reserveEnv " << size;};
};
struct let {
    static const byteCodeT type = bLet;
    uint32_t count;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "let " << count;};
};
struct closeEnv {
    static const byteCodeT type = bCloseEnv;
    std::ostream& repr(std::ostream& out, const SymbolTable&, ByteCodeChunk&) {return out << "closeEnv";};
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
        jmpInstr.ip = where.ip - ip + 1;
        set(jmpInstr);
    };
    void jump(int32_t offset) {
        ip += offset;
    };
    bool done() { return ip >= c.code.size(); };
};

template<class Visitor>
void decode(ByteCodeChunkIterator& i, Visitor v) {
    while (!i.done()) {
        byteCodeT code = (byteCodeT)i.get<uint8_t>();
        switch(code) {
        case bLoadConst: v(i.get<opcode::loadconst>()); break;
        case bLoadSymbol: v(i.get<opcode::loadsymbol>()); break;
        case bList: v(i.get<opcode::list>()); break;
        case bLoadVar: v(i.get<opcode::loadvar>()); break;
        case bLoadWith: v(i.get<opcode::loadwith>()); break;
        case bNot: v(i.get<opcode::not_>()); break;
        case bPushWith: v(i.get<opcode::pushWith>()); break;
        case bJmp: v(i.get<opcode::jmp>()); break;
        case bJmpz: v(i.get<opcode::jmpz>()); break;
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
        case bReserveEnv: v(i.get<opcode::reserveEnv>()); break;
        case bLet: v(i.get<opcode::let>()); break;
        case bCloseEnv: v(i.get<opcode::closeEnv>()); break;
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
    str << std::string(indent, ' ') << name << " (" << c.code.size() << " bytes) {" << std::endl;
    indent += 2;
    size_t cnt = 0;
    for (auto& t : c.thunks) {
        decompile(st, *t, str, "thunk " + std::to_string(cnt++), indent);
    }
    decode(i, [&](auto t) {
        str << std::string(indent, ' ');
        str << std::setw(3) << (i.ip - sizeof(t) - 1) << ": ";
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
static void eval(ByteCodeChunk& c, EvalState & state, Env & topEnv, Value & v) {
    ByteCodeChunkIterator i(c);
    std::stack<Value*> stack;
    Env * env = &topEnv;
    decode(i, match {
        [&stack, &c](opcode::loadconst op) {
            stack.push(const_cast<Value*>(c.consts[op.index]));
        },
        [&state, &stack](opcode::loadsymbol op) {
            stack.push(state.allocValue());
            stack.top()->mkString(state.symbols[op.s]);
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
            Env *e = env;
            for (auto l = op.level; l; --l, e = e->up) ;
            stack.push(e->values[op.displacement]);
        },
        [&state, &stack, &env](opcode::loadwith op) {
            ExprVar var(op.pos, op.name);
            var.fromWith = true;
            var.level = op.level;
            stack.push(state.lookupVarWith(env, var, false));
        },
        [&state, &stack](opcode::not_ op) {
            bool b = state.forceBool(*stack.top(), noPos);
            stack.top()->boolean = !b;
        },
        [&env, &stack, &state](opcode::pushWith op) {
            Env & env2(state.allocEnv(1));
            env2.up = env;
            env2.prevWith = op.prevWith;
            env2.hasWith = true;
            env2.values[0] = stack.top();
            stack.pop();
            env = &env2;
        },
        [&i](opcode::jmp op) {
            i.jump(op.ip - sizeof(op) - 1);
        },
        [&stack, &state, &i](opcode::jmpz op) {
            bool b = state.forceBool(*stack.top(), op.pos);
            stack.pop();
            if (!b) {
                i.jump(op.ip - sizeof(op) - 1);
            }
        },
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
        [&stack, &state, &env](opcode::hasAttr op) {
            AttrPath attrPath(op.attrPathLen, AttrName(nullptr));
            for (size_t i = 0; i < op.attrPathLen; i++) {
                Value *v = stack.top(); stack.pop();
                state.forceStringNoCtx(*v);
                attrPath[op.attrPathLen - i - 1].symbol = state.symbols.create(v->string.s);
            }
            Value *vTmp = stack.top(); stack.pop();
            PosIdx pos2;
            state.forceValue(*vTmp, noPos);
            stack.push(state.allocValue());
            stack.top()->mkBool(getAttrByPath(state, vTmp, *env, attrPath, noPos, [&](auto, auto) -> std::optional<Value*> {
                return {};
            }, pos2).has_value());
        },
        [&stack, &state, &env, &i](opcode::select op) {
            AttrPath attrPath(op.attrPathLen, AttrName(nullptr));
            for (size_t i = 0; i < op.attrPathLen; i++) {
                Value *v = stack.top(); stack.pop();
                state.forceStringNoCtx(*v);
                attrPath[op.attrPathLen - i - 1].symbol = state.symbols.create(v->string.s);
            }
            Value *vTmp = stack.top(); stack.pop();

            PosIdx pos2;
            state.forceValue(*vTmp, op.pos);
            // todo default, better error
            auto ret = getAttrByPath(state, vTmp, *env, attrPath, op.pos, [&](auto, auto name) -> std::optional<Value*> {
                if (op.ip != 0) return {};
                throw Error("attribute '%1%' missing, at %2%", state.symbols[name], pos2 || op.pos);
            }, pos2);
            if (ret.has_value()) {
                vTmp = ret.value();
                state.forceValue(*vTmp, pos2 ? pos2 : op.pos);
                stack.push(vTmp);
                // skip over default value
                if (op.ip != 0) i.jump(op.ip - sizeof(op) - 1);
            }
        },
        [&c, &stack, &env, &state](opcode::thunk op) {
            Value* v = state.allocValue();
            Expr *e = new ExprCompiled(*c.thunks[op.ix.idx]);
            v->mkThunk(env, e);
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
         [&state, &stack, &env](opcode::attrs op) {
            Value &v = *state.allocValue();
            auto builder = state.buildBindings(op.count);
            // only the last `recCount` bindings are recursive
            size_t recCount = op.recursive;
            for (size_t i = op.count; i > 0; i--) {
                Value *v2 = stack.top(); stack.pop();
                Value *v1 = stack.top(); stack.pop();
                state.forceValue(*v1, noPos);
                if (v1->type() == nNull) continue;
                state.forceStringNoCtx(*v1);
                builder.insert(state.symbols.create(v1->string.s), v2);
                if (recCount)
                    env->values[--recCount] = v2;
            }
            // todo: check for duplicates
            // todo: __overrides
            v.mkAttrs(builder);
            if (op.recursive) env = env->up;
            stack.push(&v);
        },
        [&stack](opcode::dup op) {
            stack.push(stack.top());
        },
        [&stack, &c, &state, &env](opcode::lambda op) {
            // todo: formals
            Expr *compiled = new ExprCompiled(*c.thunks[op.body.idx]);
            ExprLambda *l = new ExprLambda(op.pos, op.arg, nullptr, compiled);
            l->setName(op.name);
            stack.push(state.allocValue());
            stack.top()->mkLambda(env, l);
        },
        [&env, &state](opcode::reserveEnv op) {
            Env & env2(state.allocEnv(op.size));
            env2.up = env;
            env = &env2;
        },
        [&stack, &env](opcode::let op) {
            for (size_t i = op.count; i > 0; i--) {
                Value *v1 = stack.top(); stack.pop();
                env->values[i - 1] = v1;
            }
        },
        [&env](opcode::closeEnv op) {
            env = env->up;
        },
        // opcode::concatStrings
        [&](auto t) {
            assert(false);
        }
    });
    assert(stack.size() == 1);
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
void ExprSelect::compile(ByteCodeChunkIterator& c) const {
    e->compile(c);
    for (auto & i : attrPath) {
        if (i.symbol) {
            c.put(opcode::loadsymbol{i.symbol});
        } else {
            bmaybeThunk(c, i.expr);
        }
    }
    ByteCodeChunkIterator ifJmp = c.put(opcode::select{pos, (uint32_t)attrPath.size(), 0});
    if (def) {
        def->compile(c);
        ifJmp.setJmp<opcode::select>(c);
    }
};
void ExprOpHasAttr::compile(ByteCodeChunkIterator& c) const {
    e->compile(c);
    for (auto & i : attrPath) {
        if (i.symbol) {
            c.put(opcode::loadsymbol{i.symbol});
        } else {
            bmaybeThunk(c, i.expr);
        }
    }
    c.put(opcode::hasAttr{(uint32_t)attrPath.size()});
};
void ExprAttrs::compile(ByteCodeChunkIterator& c) const {
    if (recursive)
        c.put(opcode::reserveEnv{(uint32_t)(attrs.size())});
    uint32_t cnt = 0;
    for (auto & i : dynamicAttrs) {
        // todo pos
        bmaybeThunk(c, i.nameExpr);
        bmaybeThunk(c, i.valueExpr);
        cnt++;
    }
    for (auto & i : attrs) {
        // todo pos
        // todo inherits
        c.put(opcode::loadsymbol{i.first});
        bmaybeThunk(c, i.second.e);
        cnt++;
    }
    c.put(opcode::attrs{pos, cnt, recursive ? (uint32_t)attrs.size() : 0});
};
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
    c.put(opcode::reserveEnv{(uint32_t)(attrs->attrs.size())});
    uint32_t cnt = 0;
    for (auto & i : attrs->attrs) {
        // todo pos
        // todo inherits
        bmaybeThunk(c, i.second.e);
        cnt++;
    }
    c.put(opcode::let{cnt});
    body->compile(c);
    c.put(opcode::closeEnv{});

};
void ExprWith::compile(ByteCodeChunkIterator&c) const {
    bmaybeThunk(c, attrs);
    c.put(opcode::pushWith{pos, (uint16_t)prevWith});
    body->compile(c);
    c.put(opcode::closeEnv{});

};
void ExprIf::compile(ByteCodeChunkIterator&c) const {
    cond->compile(c);
    ByteCodeChunkIterator elseJmp = c.put(opcode::jmpz{pos});
    then->compile(c);
    ByteCodeChunkIterator endJmp = c.put(opcode::jmp{});
    elseJmp.setJmp<opcode::jmpz>(c);
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
