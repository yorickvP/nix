#pragma once

#include <assert.h>  // for assert
#include <string>    // for string
#include <vector>    // for vector

#include "types.hh"  // for Path
#include "util.hh"   // for AutoCloseFD

namespace nix {

class UserLock
{
private:
    Path fnUserLock;
    AutoCloseFD fdUserLock;

    bool isEnabled = false;
    std::string user;
    uid_t uid = 0;
    gid_t gid = 0;
    std::vector<gid_t> supplementaryGIDs;

public:
    UserLock();

    void kill();

    std::string getUser() { return user; }
    uid_t getUID() { assert(uid); return uid; }
    uid_t getGID() { assert(gid); return gid; }
    std::vector<gid_t> getSupplementaryGIDs() { return supplementaryGIDs; }

    bool findFreeUser();

    bool enabled() { return isEnabled; }

};

}
