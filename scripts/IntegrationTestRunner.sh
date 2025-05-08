#!/bin/bash

set -o pipefail # fail the pipeline if a command fails

base64key="EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8="
data="user_id=Username"
dotnet8image="mcr.microsoft.com/dotnet/sdk:8.0"
dotnet9image="mcr.microsoft.com/dotnet/sdk:9.0"
workingDirectory="/src/test/SharedSecret.IntegrationTests.Runner"
allTestsSuccessful=1

podman pull $dotnet8image
podman pull $dotnet9image

podman run -d --name dotnet8-container -v ./:/src --workdir $workingDirectory $dotnet8image tail -f /dev/null
podman run -d --name dotnet9-container -v ./:/src --workdir $workingDirectory $dotnet9image tail -f /dev/null

podman exec -i dotnet8-container ../../scripts/run-dotnet.sh build net8.0
podman exec -i dotnet9-container ../../scripts/run-dotnet.sh build net9.0

dotnet8output="$(podman exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 secure $base64key $data)"
echo "Verifying SharedSecret encryption from .net 8"
testresult1="$(podman exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 view $base64key $dotnet8output | xargs)"
if [ "$testresult1" != "$data" ]; then
    echo "Test failed! result '$testresult1'"
    allTestsSuccessful=0
else
    echo "Test successful!"
fi

dotnet9output="$(podman exec -i dotnet9-container ../../scripts/run-dotnet.sh run net9.0 secure $base64key $data)"
echo "Verifying SharedSecret encryption from .net 9"
testresult2="$(podman exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 view $base64key $dotnet9output | xargs)"
if [ "$testresult2" != "$data" ]; then
    echo "Test failed! result '$testresult2'"
    allTestsSuccessful=0
else
    echo "Test successful!"
fi

podman stop dotnet8-container
podman rm dotnet8-container
podman stop dotnet9-container
podman rm dotnet9-container

if [ $allTestsSuccessful -eq 1 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Tests failed!"
    exit 1
fi
