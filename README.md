Crypto - Java library for simple cryptography
=============================================
Set of simple tools for cryptography tools (e.g. hashing, encryption functions) built purely on Java SE
without any other dependency. Only JUnit is used for testing purposes.

Features
--------

-	Hashing algorithms: MD5, SHA1, SHA256 and SHA512

```java
HashingAlgorithm sha256 = new SHA256(); // or new SHA("yourEncoding") if you are not OK with UTF-8
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

-	Encryption algorithms: AES and Triple DES both using CBC (PKCS5Padding and PBKDF2 for key derivation)

```java
byte[] key = new byte[] {'m', 'y', 'k', 'e', 'y'};
EncryptionAlgorithm aes = new AES(key);

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);

String asString = aes.encrypt("hello");
String andBack2 = aes.decrypt(asString);
```