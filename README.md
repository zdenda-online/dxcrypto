Crypto - Java library for simple cryptography
=============================================
Set of simple tools for cryptography tools (e.g. hashing, encryption functions) built purely on Java SE
without any other dependency. Only JUnit is used for testing purposes.

Features
--------

- Immutable structures (algorithm instances) for thread safety
- Hashing algorithms: MD5, SHA1, SHA256 and SHA512

```java
HashingAlgorithm sha256 = new SHA256(); // or new SHA("yourEncoding")
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // 2cf24db...
```

- Encryption algorithms: AES and Triple DES both using CBC (PKCS5Padding and PBKDF2 for key derivation)

```java
byte[] key = new byte[] {'m', 'y', 'k', 'e', 'y'};
EncryptionAlgorithm aes = new AES(key);

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);

String asString = aes.encrypt("hello");
String andBack2 = aes.decrypt(asString);
```
