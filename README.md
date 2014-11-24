DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption) built purely on Java SE without transitive dependencies.

I created this library because I was tired of object initializations of existing Java APIs and all those checked
exceptions it uses. In many cases, programmer needs simpler API, so this library provides higher
level of abstraction over existing *java.security* and *javax.crypto* packages.

This library is distributed under MIT license in the hope that it will be useful, but without any warranty.
If you find any issue please contact me on my e-mail.

Maven dependency (soon in Maven Central)
----------------

```xml
<dependency>
   <groupId>cz.d1x</groupId>
   <artifactId>dxcrypto</artifactId>
   <version>1.0</version>
</dependency>
```

Features
--------

- Immutable structures of algorithms for thread safety

- Extensible for custom implementations of algorithms or only specific parts of existing ones (e.g. key derivation
for encryption or custom combination of input text and salt prior to hashing)

- Detailed javadoc for understanding what is happening under the hood

- Hashing algorithms: **MD5**, **SHA1**, **SHA256** and **SHA512**

```java
// fluent API of algorithm builders
HashingAlgorithm sha256 = HashingAlgorithms.sha256()
    .encoding(Encoding.UTF_8); // optional, defaults to UTF-8 if not specified
    .build();
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // byte[] or String based methods
```
- Additional hashing operations like **repeated hashing** or **salting**

```java
// repeated hashing
HashingAlgorithm repeatedSha512 = HashingAlgorithms.sha512()
    .repeated(27)
    .build();
String repeated = repeatedSha512.hash("hello"); // hash(hash("hello")) ~ 27x

// default salting with ConcatCombineAlgorithm
SaltingAdapter saltedSha256 = HashingAlgorithms.sha256()
    .salted()
    .build();
String salted = saltedSha256.hash("your input text", "your salt");

// salting with custom combining of input text and salt
CombineAlgorithm combineAlg = ...; // your implementation
SaltingAdapter saltedSha256 = HashingAlgorithms.sha256()
    .salted(combineAlg)
    .build();
```

- Symmetric key encryption algorithms: **AES** and **Triple DES** with CBC, PKCS#5 padding and PBKDF2 for key derivation.
Both algorithms generate a new random initialization vector for every message and combine it with cipher text into the output
(combine algorithm can be customized).

```java
EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secret")
    .keySalt("saltForKeyDerivation") // optional
    .keyHashIterations(4096) // optional
    .combineAlgorithm(...) // optional, how to combine IV + cipherText
    .build();

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);
```

```java
EncryptionAlgorithm des = EncryptionAlgorithms.tripleDes("secret")
    .build(); // default key salt, iterations count and combine alg.

String asString = des.encrypt("hello");
String andBack = des.decrypt(asString);
```

- Asymmetric (key pair) encryption algorithm: **RSA** with ECB and OAEP padding

```java
// custom keys
BigInteger modulus = ...; // your modulus (n)
BigInteger publicExponent = ...; // your public exponent (e)
BigInteger privateExponent = ...; // your private exponent (d)
EncryptionAlgorithm rsa = EncryptionAlgorithms.rsa()
        .publicKey(modulus, publicExponent)
        .privateKey(modulus, privateExponent)
        .build();
```

```java
// generated keys
RSAKeysGenerator keysGen = new RSAKeysGenerator();
KeyPair keys = keysGen.generateKeys();
EncryptionAlgorithm rsa = EncryptionAlgorithms.rsa()
        .keyPair(keys)
        .build();
```
