#!/bin/bash

set -o pipefail # fail the pipeline if a command fails

base64key="EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8="
data="user_id=Username"
dotnet8image="mcr.microsoft.com/dotnet/sdk:8.0"
dotnet9image="mcr.microsoft.com/dotnet/sdk:9.0"
workingDirectory="/src/test/SharedSecret.IntegrationTests.Runner"
allTestsSuccessful=1

# Detect container runtime: use `podman` if available, otherwise fall back to `docker`
CONTAINER_RUNTIME="docker" # Default to Docker for GitHub Actions

if command -v podman &>/dev/null; then
  CONTAINER_RUNTIME="podman"
fi

$CONTAINER_RUNTIME pull $dotnet8image
$CONTAINER_RUNTIME pull $dotnet9image

$CONTAINER_RUNTIME run -d --name dotnet8-container -v ./:/src --workdir $workingDirectory $dotnet8image tail -f /dev/null
$CONTAINER_RUNTIME run -d --name dotnet9-container -v ./:/src --workdir $workingDirectory $dotnet9image tail -f /dev/null

$CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh build net8.0
$CONTAINER_RUNTIME exec -i dotnet9-container ../../scripts/run-dotnet.sh build net9.0

dotnet8output="$($CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 secure $base64key $data)"
echo "Verifying SharedSecret encryption from .net 8"
testresult1="$($CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 view $base64key $dotnet8output | xargs)"
if [ "$testresult1" != "$data" ]; then
    echo "Test failed! result '$testresult1'"
    allTestsSuccessful=0
else
    echo "Test successful!"
fi

dotnet9output="$($CONTAINER_RUNTIME exec -i dotnet9-container ../../scripts/run-dotnet.sh run net9.0 secure $base64key $data)"
echo "Verifying SharedSecret encryption from .net 9"
testresult2="$($CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 view $base64key $dotnet9output | xargs)"
if [ "$testresult2" != "$data" ]; then
    echo "Test failed! result '$testresult2'"
    allTestsSuccessful=0
else
    echo "Test successful!"
fi

$CONTAINER_RUNTIME stop dotnet8-container
$CONTAINER_RUNTIME rm dotnet8-container
$CONTAINER_RUNTIME stop dotnet9-container
$CONTAINER_RUNTIME rm dotnet9-container

if [ $allTestsSuccessful -eq 1 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Tests failed!"
    exit 1
fi
