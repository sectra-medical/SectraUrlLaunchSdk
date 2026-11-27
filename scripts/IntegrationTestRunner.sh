#!/bin/bash

set -o pipefail # fail the pipeline if a command fails

base64key="EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8="
data="user_id=Username"
dotnet8image="mcr.microsoft.com/dotnet/sdk:8.0"
dotnet10image="mcr.microsoft.com/dotnet/sdk:10.0"
dotnet11image="mcr.microsoft.com/dotnet/sdk:11.0"
java25image="docker.io/amazoncorretto:25-jdk" # latest LTS
java27image="docker.io/amazoncorretto:27-jdk" # latest release
workingDirectory="/src/test/SharedSecret.IntegrationTests.Runner"
javaWorkingDirectory="/src/test/SharedSecret.IntegrationTests.Runner.Java"
allTestsSuccessful=1

# Detect container runtime: use `podman` if available, otherwise fall back to `docker`
CONTAINER_RUNTIME="docker" # Default to Docker for GitHub Actions

if command -v podman &>/dev/null; then
  CONTAINER_RUNTIME="podman"
fi

$CONTAINER_RUNTIME pull $dotnet8image
$CONTAINER_RUNTIME pull $dotnet10image
$CONTAINER_RUNTIME pull $dotnet11image
$CONTAINER_RUNTIME pull $java25image
$CONTAINER_RUNTIME pull $java27image

$CONTAINER_RUNTIME run -d --name dotnet8-container -v ./:/src --workdir $workingDirectory $dotnet8image tail -f /dev/null
$CONTAINER_RUNTIME run -d --name dotnet10-container -v ./:/src --workdir $workingDirectory $dotnet10image tail -f /dev/null
$CONTAINER_RUNTIME run -d --name dotnet11-container -v ./:/src --workdir $workingDirectory $dotnet11image tail -f /dev/null
$CONTAINER_RUNTIME run -d --name java25-container -v ./:/src --workdir $javaWorkingDirectory $java25image tail -f /dev/null
$CONTAINER_RUNTIME run -d --name java27-container -v ./:/src --workdir $javaWorkingDirectory $java27image tail -f /dev/null

$CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh build net8.0
$CONTAINER_RUNTIME exec -i dotnet10-container ../../scripts/run-dotnet.sh build net10.0
$CONTAINER_RUNTIME exec -i dotnet11-container ../../scripts/run-dotnet.sh build net11.0
$CONTAINER_RUNTIME exec -i java25-container ../../scripts/run-java.sh build java25
$CONTAINER_RUNTIME exec -i java27-container ../../scripts/run-java.sh build java27

# .NET 10 is the baseline. Every launch string produced by another runtime
# (including other .NET versions) is verified by decrypting it with the
# .NET 10 baseline and comparing against the original data.
verify() {
    local producer="$1"  # human-readable name of the runtime that produced $encrypted
    local encrypted="$2" # launch string produced by that runtime
    echo "Verifying SharedSecret encryption from $producer against the .NET 10 baseline"
    local result
    result="$($CONTAINER_RUNTIME exec -i dotnet10-container ../../scripts/run-dotnet.sh run net10.0 view $base64key $encrypted | xargs)"
    if [ "$result" != "$data" ]; then
        echo "Test failed! result '$result'"
        allTestsSuccessful=0
    else
        echo "Test successful!"
    fi
}

dotnet10output="$($CONTAINER_RUNTIME exec -i dotnet10-container ../../scripts/run-dotnet.sh run net10.0 secure $base64key $data)"
verify ".net 10" "$dotnet10output"

dotnet8output="$($CONTAINER_RUNTIME exec -i dotnet8-container ../../scripts/run-dotnet.sh run net8.0 secure $base64key $data)"
verify ".net 8" "$dotnet8output"

dotnet11output="$($CONTAINER_RUNTIME exec -i dotnet11-container ../../scripts/run-dotnet.sh run net11.0 secure $base64key $data)"
verify ".net 11" "$dotnet11output"

java25output="$($CONTAINER_RUNTIME exec -i java25-container ../../scripts/run-java.sh run java25 secure $base64key $data)"
verify "java 25" "$java25output"

java27output="$($CONTAINER_RUNTIME exec -i java27-container ../../scripts/run-java.sh run java27 secure $base64key $data)"
verify "java 27" "$java27output"

$CONTAINER_RUNTIME stop dotnet8-container
$CONTAINER_RUNTIME rm dotnet8-container
$CONTAINER_RUNTIME stop dotnet10-container
$CONTAINER_RUNTIME rm dotnet10-container
$CONTAINER_RUNTIME stop dotnet11-container
$CONTAINER_RUNTIME rm dotnet11-container
$CONTAINER_RUNTIME stop java25-container
$CONTAINER_RUNTIME rm java25-container
$CONTAINER_RUNTIME stop java27-container
$CONTAINER_RUNTIME rm java27-container

if [ $allTestsSuccessful -eq 1 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Tests failed!"
    exit 1
fi
