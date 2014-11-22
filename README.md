DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption) built purely on Java SE without transitive dependencies.

I created this library because I was tired of object initializations of existing Java APIs.
In many cases, a lot simplier API is needed. This library provides higher level abstraction over existing
*java.security* and *javax.crypto* packages.

If you find any issue or you would like to contribute, feel free to contact me (contact in POM).

Maven dependency (will be published to Central soon)
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

- Immutable structures (algorithm instances) for thread safety

- Extensible for custom implementations of algorithms or only specific parts of existing ones (e.g. key derivation) 

- Hashing algorithms: **MD5**, **SHA1**, **SHA256** and **SHA512**, decorator for **repeated hashing** and adapter for **salting**

```java
HashingAlgorithm sha256 = new SHA256(); // or SHA256("yourEncoding")
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // 2cf24db...

HashingAlgorithm decorator = new RepeatingDecorator(sha256, 27);
String repeated = decorator.hash("hello"); // sha256(sha256("hello")) ~ 27x

SaltingAdapter adapter = new SimpleSaltingAdapter(sha256);
String withSalt = adapter.hash("hello", "s@lt");
```

- Symmetric key encryption algorithms: **AES** and **Triple DES** both using CBC with PKCS#5 padding

```java
byte[] keyPassword = new byte[] {'m', 'y', 'k', 'e', 'y'};
EncryptionAlgorithm des = new TripleDES(keyPassword);

byte[] keySalt = new byte[] {'s', '@', 'l', 't'};
EncryptionAlgorithm aes = new AES(keyPassword, keySalt); // PBKDF2 key derivation

byte[] asBytes = des.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = des.decrypt(asBytes);

String asString = aes.encrypt("hello");
String andBack2 = aes.decrypt(asString);
```

- Asymmetric key encryption algorithm: **RSA** ECB with OAEP padding

```java
// custom keys
BigInteger modulus = ...; // your modulus (n)
BigInteger publicExponent = ...; // your public exponent (e)
BigInteger privateExponent = ...; // your private exponent (d)
EncryptionAlgorithm rsa = new RSA(modulus, publicExponent, privateExponent);

// generated keys
RSAKeysGenerator keysGenerator = new RSAKeysGenerator();
EncryptionAlgorithm rsa = new RSA(keysGenerator.getKeyPair());

String encrypted = rsa.encrypt("hello");
String decrypted = rsa.decrypt(encrypted); // hello
```
