DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption) built purely on Java SE without transitive dependencies.

I created this library because I was tired of object initializations of existing Java APIs.
In many cases, a lot simplier API is needed. This library provides higher level abstraction over existing
*java.security* and *javax.crypto* packages.

If you find any issue or you would like to contribute, feel free to contact me.

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

- Extensible for custom implementations of algorithms or only specific parts of existing ones (e.g. key derivation)

- Hashing algorithms: **MD5**, **SHA1**, **SHA256** and **SHA512**

```java
HashingAlgorithm sha256 = new SHA256();
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // String instances also accepted
```
- Additional hashing operations like **repeated hashing** or **salting**

```java
HashingAlgorithm alg = ...;

HashingAlgorithm decorator = new RepeatingDecorator(alg, 27);
String repeated = decorator.hash("hello"); // hash(hash("hello")) ~ 27x

SaltingAdapter adapter = new SaltingAdapter(alg); // DefaultConcatStrategy
String salted = adapter.hash("your input text", "your salt");
```

- Symmetric key encryption algorithms: **AES** and **Triple DES** with CBC and PKCS#5 padding.

```java
// fluent API for encryption algorithm builders
EncryptionAlgorithm aes = new AESBuilder("secret")
    .build();

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);
```

```java
EncryptionAlgorithm des = new TripleDESBuilder("secret")
    .keySalt("saltForKeyDerivation") // optional
    .iterations(27) // optional
    .build();

String asString = des.encrypt("hello");
String andBack = des.decrypt(asString);
```


- Asymmetric (key pair) encryption algorithm: **RSA** with ECB and OAEP padding

```java
// custom keys
BigInteger modulus = ...; // your modulus (n)
BigInteger publicExponent = ...; // your public exponent (e)
BigInteger privateExponent = ...; // your private exponent (d)
EncryptionAlgorithm rsa = new RSABuilder()
        .publicKey(modulus, publicExponent)
        .privateKey(modulus, privateExponent)
        .build();
```

```java
// generated keys
RSAKeysGenerator keysGen = new RSAKeysGenerator();
KeyPair keys = keysGen.generateKeys();
EncryptionAlgorithm rsa = new RSABuilder()
        .keyPair(keys)
        .build();
```
