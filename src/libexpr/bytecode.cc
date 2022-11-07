#include "eval.hh"
#include "bytecode.hh"
#include "nixexpr.hh"
namespace nix {

void decompile(SymbolTable& st, ByteCodeChunk& c, uint32_t ix, std::ostream & str) {
    while (ix < c.code.size()) {
        byteCodeT code = (byteCodeT)c.code[ix++];
        switch(code) {
        case bLoadConst:
            str << "pushval(";
            c.get_val(ix)->print(st, str);
            str << ")" << std::endl;
            ix += 4;
            break;
        case bList:
            str << "list(" << c.get_u32(ix) << ")" << std::endl;
            ix += 4;
            break;
        case bLoadVar: {
            uint32_t val;
            val = c.get_u32(ix+4);
            Symbol* t = reinterpret_cast<Symbol*>(&val);
            str << "load(" << st[*t] << ")" << std::endl;
            ix += 4 + 4 + 1 + 4 + 4;
        }; break;
        case bNot: str << "not" << std::endl; break;
        case bWith: str << "pushWith" << std::endl; ix += 2; break;
        case bPopEnv: str << "popWith" << std::endl; break;
        case bJmp: str << "jmp(" << c.get_u32(ix) << ")" << std::endl; ix += 4; break;
        case bIf: str << "jmpnot(" << c.get_u32(ix+4) << ")" << std::endl; ix += 8; break;
        case bOpEq: str << "eq" << std::endl; ix += 4; break;
        case bOpNEq: str << "neq" << std::endl; ix += 4; break;
        case bOpAnd: str << "and" << std::endl; ix += 4; break;
        case bOpOr: str << "or" << std::endl; ix += 4; break;
        case bOpImpl: str << "impl" << std::endl; ix += 4; break;
        case bOpUpdate: str << "update" << std::endl; ix += 4; break;
        case bOpConcatList: str << "concatList" << std::endl; ix += 4; break;
        case bPos: str << "curPos" << std::endl; ix += 4; break;
        case bCall: str << "call(" << (uint32_t)(c.code[ix+4]) << ")" << std::endl; ix+= 5; break;
        case bHasAttr: str << "hasattr(" << c.get_attrPath(ix) << ")" << std::endl; ix += 4; break;
        case bSelect: str << "select(" << c.get_attrPath(ix+4) << ")" << std::endl; ix += 8; break;
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
    c.push(bLoadVar);
    pushPos(c, pos);
    c.push(*reinterpret_cast<const uint32_t*>(&name));
    c.push(fromWith);
    c.push((uint32_t)level);
    c.push((uint32_t)displ);
};
void ExprSelect::compile(ByteCodeChunk & c) const {
    e->compile(c);
    if (def) {
        c.push(bDup);
        c.push(bHasAttr);
        c.push(attrPath);
        c.push(bNot);
        c.push(bIf);
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

};
void ExprList::compile(ByteCodeChunk & c) const {
    uint32_t cnt = 0;
    for (auto i : elems) {
        i->compile(c);
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
        i->compile(c);
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
    c.push(bPopEnv);

};
void ExprIf::compile(ByteCodeChunk &c) const {
    cond->compile(c);
    c.push(bIf);
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
}
