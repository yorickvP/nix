#include <stddef.h>                  // for size_t
#include <boost/format.hpp>          // for basic_altstringbuf<>::int_type
#include <map>                       // for map<>::mapped_type
#include <memory>                    // for allocator, shared_ptr, __shared_...
#include <optional>                  // for optional
#include <string>                    // for string, operator!=, basic_string
#include <string_view>               // for string_view
#include <utility>                   // for pair
#include <vector>                    // for vector

#include "command.hh"                // for completeFlakeRef, registerCommand
#include "fetchers.hh"               // for Input
#include "registry.hh"               // for Registry, Registry::Entry, getCu...
#include "args.hh"                   // for Command, Args, Command::Category
#include "attrs.hh"                  // for Attrs, attrsToQuery, fetchers
#include "common-eval-args.hh"       // for MixEvalArgs
#include "error.hh"                  // for UsageError
#include "experimental-features.hh"  // for Xp
#include "flake/flakeref.hh"         // for parseFlakeRef, FlakeRef
#include "globals.hh"                // for Settings, settings
#include "logging.hh"                // for Logger, logger
#include "ref.hh"                    // for make_ref, ref, nix
#include "types.hh"                  // for Path
#include "installables.hh"           // for flake

namespace nix {
class Store;
}  // namespace nix

using namespace nix;
using namespace nix::flake;


class RegistryCommand : virtual Args
{
    std::string registry_path;

    std::shared_ptr<fetchers::Registry> registry;

public:

    RegistryCommand()
    {
        addFlag({
            .longName = "registry",
            .description = "The registry to operate on.",
            .labels = {"registry"},
            .handler = {&registry_path},
        });
    }

    std::shared_ptr<fetchers::Registry> getRegistry()
    {
        if (registry) return registry;
        if (registry_path.empty()) {
            registry = fetchers::getUserRegistry();
        } else {
            registry = fetchers::getCustomRegistry(registry_path);
        }
        return registry;
    }

    Path getRegistryPath()
    {
        if (registry_path.empty()) {
            return fetchers::getUserRegistryPath();
        } else {
            return registry_path;
        }
    }
};

struct CmdRegistryList : StoreCommand
{
    std::string description() override
    {
        return "list available Nix flakes";
    }

    std::string doc() override
    {
        return
          #include "registry-list.md"

          ;
    }

    void run(nix::ref<nix::Store> store) override
    {
        using namespace fetchers;

        auto registries = getRegistries(store);

        for (auto & registry : registries) {
            for (auto & entry : registry->entries) {
                // FIXME: format nicely
                logger->cout("%s %s %s",
                    registry->type == Registry::Flag   ? "flags " :
                    registry->type == Registry::User   ? "user  " :
                    registry->type == Registry::System ? "system" :
                    "global",
                    entry.from.toURLString(),
                    entry.to.toURLString(attrsToQuery(entry.extraAttrs)));
            }
        }
    }
};

struct CmdRegistryAdd : MixEvalArgs, Command, RegistryCommand
{
    std::string fromUrl, toUrl;

    std::string description() override
    {
        return "add/replace flake in user flake registry";
    }

    std::string doc() override
    {
        return
          #include "registry-add.md"

          ;
    }

    CmdRegistryAdd()
    {
        expectArg("from-url", &fromUrl);
        expectArg("to-url", &toUrl);
    }

    void run() override
    {
        auto fromRef = parseFlakeRef(fromUrl);
        auto toRef = parseFlakeRef(toUrl);
        auto registry = getRegistry();
        fetchers::Attrs extraAttrs;
        if (toRef.subdir != "") extraAttrs["dir"] = toRef.subdir;
        registry->remove(fromRef.input);
        registry->add(fromRef.input, toRef.input, extraAttrs);
        registry->write(getRegistryPath());
    }
};

struct CmdRegistryRemove : RegistryCommand, Command
{
    std::string url;

    std::string description() override
    {
        return "remove flake from user flake registry";
    }

    std::string doc() override
    {
        return
          #include "registry-remove.md"

          ;
    }

    CmdRegistryRemove()
    {
        expectArg("url", &url);
    }

    void run() override
    {
        auto registry = getRegistry();
        registry->remove(parseFlakeRef(url).input);
        registry->write(getRegistryPath());
    }
};

struct CmdRegistryPin : RegistryCommand, EvalCommand
{
    std::string url;

    std::string locked;

    std::string description() override
    {
        return "pin a flake to its current version or to the current version of a flake URL";
    }

    std::string doc() override
    {
        return
          #include "registry-pin.md"

          ;
    }

    CmdRegistryPin()
    {
        expectArg("url", &url);

        expectArgs({
            .label = "locked",
            .optional = true,
            .handler = {&locked},
            .completer = {[&](size_t, std::string_view prefix) {
                completeFlakeRef(getStore(), prefix);
            }}
        });
    }

    void run(nix::ref<nix::Store> store) override
    {
        if (locked.empty()) {
            locked = url;
        }
        auto registry = getRegistry();
        auto ref = parseFlakeRef(url);
        auto locked_ref = parseFlakeRef(locked);
        registry->remove(ref.input);
        auto [tree, resolved] = locked_ref.resolve(store).input.fetch(store);
        fetchers::Attrs extraAttrs;
        if (ref.subdir != "") extraAttrs["dir"] = ref.subdir;
        registry->add(ref.input, resolved, extraAttrs);
        registry->write(getRegistryPath());
    }
};

struct CmdRegistry : virtual NixMultiCommand
{
    CmdRegistry()
        : MultiCommand({
                {"list", []() { return make_ref<CmdRegistryList>(); }},
                {"add", []() { return make_ref<CmdRegistryAdd>(); }},
                {"remove", []() { return make_ref<CmdRegistryRemove>(); }},
                {"pin", []() { return make_ref<CmdRegistryPin>(); }},
            })
    {
    }

    std::string description() override
    {
        return "manage the flake registry";
    }

    std::string doc() override
    {
        return
          #include "registry.md"

          ;
    }

    Category category() override { return catSecondary; }

    void run() override
    {
        settings.requireExperimentalFeature(Xp::Flakes);
        if (!command)
            throw UsageError("'nix registry' requires a sub-command.");
        command->second->prepare();
        command->second->run();
    }
};

static auto rCmdRegistry = registerCommand<CmdRegistry>("registry");
