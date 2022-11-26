#pragma once

#include <map>           // for map

#include "logging.hh"    // for ActivityId, Activity
#include "serialise.hh"  // for FdSink
#include "util.hh"       // for Pipe, Pid

namespace nix {

struct HookInstance
{
    /* Pipes for talking to the build hook. */
    Pipe toHook;

    /* Pipe for the hook's standard output/error. */
    Pipe fromHook;

    /* Pipe for the builder's standard output/error. */
    Pipe builderOut;

    /* The process ID of the hook. */
    Pid pid;

    FdSink sink;

    std::map<ActivityId, Activity> activities;

    HookInstance();

    ~HookInstance();
};

}
