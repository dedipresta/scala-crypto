# SCALA-CRYPTO

[![Scala 2.12](https://img.shields.io/badge/Scala-2.12-blue)](https://www.scala-lang.org/)
[![Scala 2.13](https://img.shields.io/badge/Scala-2.13-blue)](https://www.scala-lang.org/)
[![Scala.js](https://www.scala-js.org/assets/badges/scalajs-1.1.0.svg)](https://www.scala-js.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blueviolet.svg)](https://opensource.org/licenses/MIT)
![version](https://img.shields.io/badge/version-0.1.0-success.svg)
[![made with love](https://img.shields.io/badge/Made_with-❤-red.svg)](https://www.dedipresta.com)


Scala Crypto is a dependency free implementation of cryptographic hash functions.

It targets Scala and Scala.js.

## Why Scala Crypto ?
All Scala SHA-256 hash libraries rely on Java libraries, especially `java.security.MessageDigest`
and thus cannot be used in the context of a `scala.js` application or library.
Having a dependency free library allows to publish for other platforms than JVM and in addition to `scala.js`
this library will be published to `scala-native` once support for Scala support for 2.12 and 2.13
will be available.


## Supported algorithms

| Supported algorithms |  Information                  |
|----------------------|-------------------------------|
| *SHA-256*            | Inspired by java implementation  [meyfa/java-sha256](https://github.com/meyfa/java-sha256)|

## How to use

Add to your sbt project:

*Scala:*
```Scala
libraryDependencies += "com.dedipresta" %% "scala-crypto-sha256" % "0.1.0"
```
*Scala.js:*
```Scala
libraryDependencies += "com.dedipresta" %%% "scala-crypto-sha256" % "0.1.0"
```

Then you may hash your `String` or `Array[Byte]`:
```Scala
import com.dedipresta.crypto.hash.sha256.Sha256
Sha256.hash("Hello world!") // to get an array of bytes
Sha256.hashString("Scala.js!") // 25ed477793a2663fc5173a24f1a1f0750d5bd7f577dabee09452d82d3caff0e2
```

### Copyright and License

All code is available to you under the MIT license, available at
[https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT) and also in the
[LICENSE](LICENSE) file.
