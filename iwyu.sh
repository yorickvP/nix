#!/usr/bin/env bash
iwyu_tool.py -p . "$@" -- \
  -Xiwyu --mapping_file=$PWD/.includes.imp \
  -Xiwyu --cxx17ns \
  -Xiwyu --transitive_includes_only \
  -Xiwyu --keep="*callback.hh*" -Xiwyu --keep="*.md" \
  -Xiwyu --keep="*abstract-setting-to-json.hh" \
  -Xiwyu --keep="*.gen.hh" | tee iwyu_diff

cat iwyu_diff | fix_includes.py -p $PWD --separate_project_includes=. --nosafe_headers --comments
