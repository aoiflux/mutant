#!/usr/bin/env sh
set -e

step="$1"
mutant gen --src "examples/workshop/$step.mut" --dev
mutant "examples/workshop/$step.mu" --dev
