#!/bin/bash

set -e # stop immediately after a failure
set -o pipefail # fail the pipeline if a command fails

JavaCommand=$1
# One output directory per JDK: classes compiled by a newer JDK cannot be loaded by an older one.
BuildDirectory=./build/$2

if [ "$JavaCommand" == "build" ]; then
    javac -d $BuildDirectory Main.java ../../src/Java/EncryptionUtils.java ../../src/Java/Hkdf.java ../../src/Java/SectraUrlLaunchSharedSecret.java ../../src/Java/SignatureUtils.java
    exit 0
fi

if [ "$JavaCommand" == "run" ]; then
    shift 2
    java -cp $BuildDirectory Main $@
    exit 0
fi

exit 1
