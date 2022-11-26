#include <boost/format.hpp>    // for basic_altstringbuf<>::int_type, basic_...
#include <sstream>             // for operator<<, basic_ostream, stringstream
#include <list>                // for list, operator!=, _List_iterator, _Lis...
#include <map>                 // for operator!=, _Rb_tree_const_iterator
#include <memory>              // for allocator, shared_ptr
#include <optional>            // for optional
#include <string>              // for string, char_traits, basic_string, ope...

#include "command.hh"          // for registerCommand, StoreCommand, catNixI...
#include "logging.hh"          // for Logger, notice, logger
#include "serve-protocol.hh"   // for SERVE_PROTOCOL_VERSION
#include "shared.hh"           // for Exit
#include "store-api.hh"        // for Store
#include "util.hh"             // for dirOf, canonPath, getEnv, tokenizeString
#include "worker-protocol.hh"  // for GET_PROTOCOL_MAJOR, GET_PROTOCOL_MINOR
#include "ansicolor.hh"        // for ANSI_NORMAL, ANSI_GREEN, ANSI_RED
#include "args.hh"             // for Command::Category
#include "error.hh"            // for SysError
#include "fmt.hh"              // for format
#include "globals.hh"          // for Settings, settings
#include "ref.hh"              // for ref, nix
#include "types.hh"            // for Path, PathSet, Strings, PathView
#include "local-fs-store.hh"   // for LocalFSStore

// IWYU pragma: no_forward_declare nix::LocalFSStore

using namespace nix;

namespace {

std::string formatProtocol(unsigned int proto)
{
    if (proto) {
        auto major = GET_PROTOCOL_MAJOR(proto) >> 8;
        auto minor = GET_PROTOCOL_MINOR(proto);
        return (format("%1%.%2%") % major % minor).str();
    }
    return "unknown";
}

bool checkPass(const std::string & msg) {
    notice(ANSI_GREEN "[PASS] " ANSI_NORMAL + msg);
    return true;
}

bool checkFail(const std::string & msg) {
    notice(ANSI_RED "[FAIL] " ANSI_NORMAL + msg);
    return false;
}

}

struct CmdDoctor : StoreCommand
{
    bool success = true;

    std::string description() override
    {
        return "check your system for potential problems and print a PASS or FAIL for each check";
    }

    Category category() override { return catNixInstallation; }

    void run(ref<Store> store) override
    {
        logger->log("Running checks against store uri: " + store->getUri());

        if (store.dynamic_pointer_cast<LocalFSStore>()) {
            success &= checkNixInPath();
            success &= checkProfileRoots(store);
        }
        success &= checkStoreProtocol(store->getProtocol());

        if (!success)
            throw Exit(2);
    }

    bool checkNixInPath()
    {
        PathSet dirs;

        for (auto & dir : tokenizeString<Strings>(getEnv("PATH").value_or(""), ":"))
            if (pathExists(dir + "/nix-env"))
                dirs.insert(dirOf(canonPath(dir + "/nix-env", true)));

        if (dirs.size() != 1) {
            std::stringstream ss;
            ss << "Multiple versions of nix found in PATH:\n";
            for (auto & dir : dirs)
                ss << "  " << dir << "\n";
            return checkFail(ss.str());
        }

        return checkPass("PATH contains only one nix version.");
    }

    bool checkProfileRoots(ref<Store> store)
    {
        PathSet dirs;

        for (auto & dir : tokenizeString<Strings>(getEnv("PATH").value_or(""), ":")) {
            Path profileDir = dirOf(dir);
            try {
                Path userEnv = canonPath(profileDir, true);

                if (store->isStorePath(userEnv) && hasSuffix(userEnv, "user-environment")) {
                    while (profileDir.find("/profiles/") == std::string::npos && isLink(profileDir))
                        profileDir = absPath(readLink(profileDir), dirOf(profileDir));

                    if (profileDir.find("/profiles/") == std::string::npos)
                        dirs.insert(dir);
                }
            } catch (SysError &) {}
        }

        if (!dirs.empty()) {
            std::stringstream ss;
            ss << "Found profiles outside of " << settings.nixStateDir << "/profiles.\n"
               << "The generation this profile points to might not have a gcroot and could be\n"
               << "garbage collected, resulting in broken symlinks.\n\n";
            for (auto & dir : dirs)
                ss << "  " << dir << "\n";
            ss << "\n";
            return checkFail(ss.str());
        }

        return checkPass("All profiles are gcroots.");
    }

    bool checkStoreProtocol(unsigned int storeProto)
    {
        unsigned int clientProto = GET_PROTOCOL_MAJOR(SERVE_PROTOCOL_VERSION) == GET_PROTOCOL_MAJOR(storeProto)
            ? SERVE_PROTOCOL_VERSION
            : PROTOCOL_VERSION;

        if (clientProto != storeProto) {
            std::stringstream ss;
            ss << "Warning: protocol version of this client does not match the store.\n"
               << "While this is not necessarily a problem it's recommended to keep the client in\n"
               << "sync with the daemon.\n\n"
               << "Client protocol: " << formatProtocol(clientProto) << "\n"
               << "Store protocol: " << formatProtocol(storeProto) << "\n\n";
            return checkFail(ss.str());
        }

        return checkPass("Client protocol matches store protocol.");
    }
};

static auto rCmdDoctor = registerCommand<CmdDoctor>("doctor");
