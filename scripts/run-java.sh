#!/bin/bash

set -e # stop immediately after a failure
set -o pipefail # fail the pipeline if a command fails

JavaCommand=$1

if [ "$JavaCommand" == "build" ]; then
    javac -d ./build Main.java ../../src/Java/EncryptionUtils.java ../../src/Java/Hkdf.java ../../src/Java/SectraUrlLaunchSharedSecret.java ../../src/Java/SignatureUtils.java
    exit 0
fi

if [ "$JavaCommand" == "run" ]; then
    shift 1
    java -cp ./build Main $@
    exit 0
fi

exit 1
