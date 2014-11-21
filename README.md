DXCrypto: Easy Java Cryptography
================================
Set of simple tools for cryptography (hashing and encryption) built purely on Java SE (no transitive dependencies).

I created this library because I was tired of using existing Java API for hashing and encryption algorithms.
In most cases, you expect much more simple API, so this is only an abstraction built on existing
*java.security* and *javax.crypto* packages.

If you find any issue or you would like to contribute, feel free to contact me.

Features
--------

- Immutable structures (algorithm instances) for thread safety
- Hashing algorithms: **MD5**, **SHA1**, **SHA256** and **SHA512**

```java
HashingAlgorithm sha256 = new SHA256(); // or SHA256("yourEncoding")
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // 2cf24db...
```

- Encryption algorithms: **AES** and **Triple DES** both using CBC with PKCS #5 padding

```java
byte[] key = new byte[] {'m', 'y', 'k', 'e', 'y'};
EncryptionAlgorithm aes = new AES(key); // or AES(key, "yourEncoding")

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);

String asString = aes.encrypt("hello");
String andBack2 = aes.decrypt(asString);
```
