#include <sys/stat.h>        // for mkdir
#include <boost/format.hpp>  // for basic_altstringbuf<>::int_type, basic_al...
#include <functional>        // for function
#include <iostream>          // for cout, endl, ostream
#include <memory>            // for allocator, __shared_ptr_access, shared_ptr
#include <optional>          // for optional
#include <string>            // for string, char_traits, basic_string
#include <string_view>       // for operator==, operator<<, basic_string_view

#include "command.hh"        // for registerCommand, InstallableCommand, cat...
#include "common-args.hh"    // for MixJSON
#include "eval.hh"           // for EvalState, printValue
#include "eval-inline.hh"    // for EvalState::allocValue, EvalState::forceV...
#include "json.hh"           // for JSONPlaceholder
#include "value-to-json.hh"  // for printValueAsJSON
#include "progress-bar.hh"   // for stopProgressBar
#include "args.hh"           // for Command::Category
#include "attr-set.hh"       // for Attr, Bindings
#include "error.hh"          // for Error, ErrPos, UsageError, SysError
#include "fmt.hh"            // for hintfmt
#include "installables.hh"   // for Installable
#include "logging.hh"        // for Logger, logger
#include "nixexpr.hh"        // for Pos, PosTable, noPos, PosIdx, TypeError
#include "ref.hh"            // for ref, nix
#include "symbol-table.hh"   // for SymbolStr, SymbolTable
#include "types.hh"          // for Path, BackedStringView, PathSet
#include "util.hh"           // for absPath, concatStrings, pathExists, writ...
#include "value.hh"          // for Value, Value::(anonymous), Value::(anony...

namespace nix {
class Store;
}  // namespace nix

using namespace nix;

struct CmdEval : MixJSON, InstallableCommand
{
    bool raw = false;
    std::optional<std::string> apply;
    std::optional<Path> writeTo;

    CmdEval() : InstallableCommand(true /* supportReadOnlyMode */)
    {
        addFlag({
            .longName = "raw",
            .description = "Print strings without quotes or escaping.",
            .handler = {&raw, true},
        });

        addFlag({
            .longName = "apply",
            .description = "Apply the function *expr* to each argument.",
            .labels = {"expr"},
            .handler = {&apply},
        });

        addFlag({
            .longName = "write-to",
            .description = "Write a string or attrset of strings to *path*.",
            .labels = {"path"},
            .handler = {&writeTo},
        });
    }

    std::string description() override
    {
        return "evaluate a Nix expression";
    }

    std::string doc() override
    {
        return
          #include "eval.md"

          ;
    }

    Category category() override { return catSecondary; }

    void run(ref<Store> store) override
    {
        if (raw && json)
            throw UsageError("--raw and --json are mutually exclusive");

        auto state = getEvalState();

        auto [v, pos] = installable->toValue(*state);
        PathSet context;

        if (apply) {
            auto vApply = state->allocValue();
            state->eval(state->parseExprFromString(*apply, absPath(".")), *vApply);
            auto vRes = state->allocValue();
            state->callFunction(*vApply, *v, *vRes, noPos);
            v = vRes;
        }

        if (writeTo) {
            stopProgressBar();

            if (pathExists(*writeTo))
                throw Error("path '%s' already exists", *writeTo);

            std::function<void(Value & v, const PosIdx pos, const Path & path)> recurse;

            recurse = [&](Value & v, const PosIdx pos, const Path & path)
            {
                state->forceValue(v, pos);
                if (v.type() == nString)
                    // FIXME: disallow strings with contexts?
                    writeFile(path, v.string.s);
                else if (v.type() == nAttrs) {
                    if (mkdir(path.c_str(), 0777) == -1)
                        throw SysError("creating directory '%s'", path);
                    for (auto & attr : *v.attrs) {
                        std::string_view name = state->symbols[attr.name];
                        try {
                            if (name == "." || name == "..")
                                throw Error("invalid file name '%s'", name);
                            recurse(*attr.value, attr.pos, concatStrings(path, "/", name));
                        } catch (Error & e) {
                            e.addTrace(
                                state->positions[attr.pos],
                                hintfmt("while evaluating the attribute '%s'", name));
                            throw;
                        }
                    }
                }
                else
                    throw TypeError("value at '%s' is not a string or an attribute set", state->positions[pos]);
            };

            recurse(*v, pos, *writeTo);
        }

        else if (raw) {
            stopProgressBar();
            std::cout << *state->coerceToString(noPos, *v, context);
        }

        else if (json) {
            JSONPlaceholder jsonOut(std::cout);
            printValueAsJSON(*state, true, *v, pos, jsonOut, context, false);
            std::cout << std::endl;
        }

        else {
            state->forceValueDeep(*v);
            logger->cout("%s", printValue(*state, *v));
        }
    }
};

static auto rCmdEval = registerCommand<CmdEval>("eval");
