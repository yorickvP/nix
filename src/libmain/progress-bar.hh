#pragma once

namespace nix {
class Logger;

Logger * makeProgressBar();

void startProgressBar();

void stopProgressBar();

}
