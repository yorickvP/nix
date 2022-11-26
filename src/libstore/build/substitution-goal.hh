#pragma once

#include <stdint.h>            // for uint64_t
#include <stdlib.h>            // for abort
#include <future>
#include <list>                // for list
#include <memory>              // for allocator, unique_ptr, shared_ptr
#include <optional>            // for optional, nullopt
#include <string>              // for string, char_traits, operator+
#include <string_view>         // for string_view
#include <thread>              // for thread

#include "store-api.hh"        // for Store
#include "goal.hh"             // for Goal, Goal::ExitCode
#include "build-result.hh"     // for BuildResult, BuildResult::Status
#include "content-address.hh"  // for ContentAddress
#include "error.hh"            // for Error
#include "path.hh"             // for StorePath
#include "ref.hh"              // for ref
#include "repair-flag.hh"      // for NoRepair, RepairFlag
#include "types.hh"            // for Path
#include "util.hh"             // for MaintainCount (ptr only), Pipe

namespace nix {

class Worker;
struct ValidPathInfo;

struct PathSubstitutionGoal : public Goal
{
    /* The store path that should be realised through a substitute. */
    StorePath storePath;

    /* The path the substituter refers to the path as. This will be
       different when the stores have different names. */
    std::optional<StorePath> subPath;

    /* The remaining substituters. */
    std::list<ref<Store>> subs;

    /* The current substituter. */
    std::shared_ptr<Store> sub;

    /* Whether a substituter failed. */
    bool substituterFailed = false;

    /* Path info returned by the substituter's query info operation. */
    std::shared_ptr<const ValidPathInfo> info;

    /* Pipe for the substituter's standard output. */
    Pipe outPipe;

    /* The substituter thread. */
    std::thread thr;

    std::promise<void> promise;

    /* Whether to try to repair a valid path. */
    RepairFlag repair;

    /* Location where we're downloading the substitute.  Differs from
       storePath when doing a repair. */
    Path destPath;

    std::unique_ptr<MaintainCount<uint64_t>> maintainExpectedSubstitutions,
        maintainRunningSubstitutions, maintainExpectedNar, maintainExpectedDownload;

    typedef void (PathSubstitutionGoal::*GoalState)();
    GoalState state;

    /* Content address for recomputing store path */
    std::optional<ContentAddress> ca;

    void done(
        ExitCode result,
        BuildResult::Status status,
        std::optional<std::string> errorMsg = {});

public:
    PathSubstitutionGoal(const StorePath & storePath, Worker & worker, RepairFlag repair = NoRepair, std::optional<ContentAddress> ca = std::nullopt);
    ~PathSubstitutionGoal();

    void timedOut(Error && ex) override { abort(); };

    std::string key() override
    {
        /* "a$" ensures substitution goals happen before derivation
           goals. */
        return "a$" + std::string(storePath.name()) + "$" + worker.store.printStorePath(storePath);
    }

    void work() override;

    /* The states. */
    void init();
    void tryNext();
    void gotInfo();
    void referencesValid();
    void tryToRun();
    void finished();

    /* Callback used by the worker to write to the log. */
    void handleChildOutput(int fd, std::string_view data) override;
    void handleEOF(int fd) override;

    void cleanup() override;
};

}
