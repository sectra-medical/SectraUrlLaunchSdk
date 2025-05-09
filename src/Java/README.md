# Sectra URL Launch SDK Java

This is the Java version of a subset of the C# reference implementation of the Sectra URL Launch SDK.

## Building a jar library

```bash
javac -d ./build EncryptionUtils.java Hkdf.java SectraUrlLaunchSharedSecret.java SignatureUtils.java
cd build
jar cf ../SectraUrlLaunchSdk.jar *.class
```
