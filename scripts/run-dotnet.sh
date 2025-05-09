#!/bin/bash

set -e # stop immediately after a failure
set -o pipefail # fail the pipeline if a command fails

DotnetCommand=$1
DotnetFramework=$2

if [ "$DotnetCommand" == "build" ]; then
    dotnet build -p:TargetFrameworks=$DotnetFramework --framework $DotnetFramework
    exit 0
fi

if [ "$DotnetCommand" == "run" ]; then
    shift 2
    dotnet run --no-build -p:TargetFrameworks=$DotnetFramework --framework $DotnetFramework -- $@
    exit 0
fi

exit 1