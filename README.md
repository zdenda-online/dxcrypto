DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption) built purely on Java SE without transitive dependencies.

I created this library because I was tired of object initializations of existing Java APIs and all those checked
exceptions you have to take care of. In many cases, programmer needs simpler API, so this library provides higher
level of abstraction over existing *java.security* and *javax.crypto* packages.

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

- Hashing algorithms: **MD5**, **SHA1**, **SHA256** and **SHA512**

```java
HashingAlgorithm sha256 = new SHA256();
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // String instances also accepted
```
- Additional hashing operations like **repeated hashing** or **salting**

```java
HashingAlgorithm hashAlg = ...;

// repeated hashing
HashingAlgorithm decorator = new RepeatingDecorator(hashAlg, 27);
String repeated = decorator.hash("hello"); // hash(hash("hello")) ~ 27x

// default salting
SaltingAdapter adapter = new SaltingAdapter(hashAlg);
String salted = adapter.hash("your input text", "your salt");

// salting with custom combine algorithm
CombineAlgorithm combineAlg = ...; // your implementation
SaltingAdapter adapter = new SaltingAdapter(hashAlg, combineAlg); // ConcatCombineAlgorithm
```

- Symmetric key encryption algorithms: **AES** and **Triple DES** with CBC, PKCS#5 padding and PBKDF2 for key derivation.
Both algorithms generate a new random initialization vector for every message and combine it with cipher text to output,
so instances are later able to derive this vector during decryption.

```java
// fluent API for encryption algorithm builders
EncryptionAlgorithm aes = new AESBuilder("secret")
    .keySalt("saltForKeyDerivation") // optional
    .keyHashIterations(4096) // optional
    .combineAlgorithm(...) // optional
    .build();

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);
```

```java
EncryptionAlgorithm des = new TripleDESBuilder("secret")
    .build(); // default salt and iterations count

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
