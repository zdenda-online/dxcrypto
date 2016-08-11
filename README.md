DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption) built purely on Java SE without any dependencies.

I created this library because I was tired of object initializations of existing Java APIs and all those checked
exceptions it uses. In many cases, programmer needs simpler API, so this library provides higher
level of abstraction over existing *java.security* and *javax.crypto* packages. You can be sure it uses implementations
of cryptographic functions from JDK. In other words if you trust implementations in JDK, you can trust this library.

It also provides few utility classes like SecureProperties that extend existing *java.util.Properties* with
encrypted properties.

This library is distributed under MIT license in the hope that it will be useful, but without any warranty.
If you find any issue, please contact me on my e-mail.

Maven dependency
----------------

```xml
<dependency>
   <groupId>cz.d1x</groupId>
   <artifactId>dxcrypto</artifactId>
   <version>1.11</version>
</dependency>
```

Features
--------

- Immutable structures of algorithms for thread safety

- Extensible for custom implementations of algorithms or only specific parts of existing ones (e.g. key derivation
for encryption, custom combination of input text and salt prior to hashing...etc)

- Detailed javadoc for understanding what is happening under the hood

- Hashing algorithms **MD5**, **SHA1**, **SHA256**, **SHA512** and additional operations of **repeated hashing** 
and **salting** 

- Symmetric encryption algorithms **AES** and **Triple DES** with CBC, PKCS#5 padding and PBKDF2 for key derivation.
Both algorithms generate a new random initialization vector for every message and combine it with cipher text
into the output.

- Asymmetric encryption algorithm **RSA** with ECB and OAEP padding

- **SecureProperties** that extend *java.util.Properties* by adding possibility to store/read encrypted values

Examples
--------
**Hashing**
```java
HashingAlgorithm sha256 = HashingAlgorithms.sha256()
    .encoding("UTF-8") // optional, defaults to UTF-8
    .bytesRepresentation(...) // optional, defaults to lower-cased HEX
    .build();

// byte[] or String based methods
byte[] asBytes = sha256.hash(new byte[] {'h', 'e', 'l', 'l', 'o'});
String asString = sha256.hash("hello"); // 2cf24dba5fb0a...

// repeated hashing
HashingAlgorithm repeatedSha512 = HashingAlgorithms.sha512()
    .repeated(27)
    .build();
String repeated = repeatedSha512.hash("hello"); // hash(hash("hello")) ~ 27x

// salting (with default combining of input text and salt)
SaltedHashingAlgorithm saltedSha256 = HashingAlgorithms.sha256()
    .salted()
    .build();
String salted = saltedSha256.hash("your input text", "your salt");

// salting with custom combining of input text and salt
Combining combining = ...; // your implementation
SaltedHashingAlgorithm customSaltedSha256 = HashingAlgorithms.sha256()
    .salted(combining)
    .build();
```

**Symmetric Encryption**
```java
// AES
EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secretPassphrase")
    .keySalt("saltForKeyDerivation") // optional
    .keyHashIterations(4096) // optional
    .ivFactory(...) // optional, how IV is generated, defaults to random bytes
    .ivOutputCombining(...) // optional, how to combine/split IV and input
    .bytesRepresentation(...) // optional, defaults to lower-cased HEX
    .build();

byte[] asBytes = aes.encrypt(new byte[] {'h', 'e', 'l', 'l', 'o'});
byte[] andBack = aes.decrypt(asBytes);

// DES
EncryptionAlgorithm des = EncryptionAlgorithms.tripleDes("secret")
    .build(); // default key salt, iterations count and combine/split alg.

String asString = des.encrypt("hello");
String andBack = des.decrypt(asString);
```

**Asymmetric Encryption**
```java
// custom keys
BigInteger modulus = BigInteger.ZERO; // your modulus (n)
BigInteger publicExponent = BigInteger.ZERO; // your public exponent (e)
BigInteger privateExponent = BigInteger.ZERO; // your private exponent (d)
EncryptionAlgorithm customRsa = EncryptionAlgorithms.rsa()
    .publicKey(modulus, publicExponent)
    .privateKey(modulus, privateExponent)
    .build();

// generated keys
RSAKeysGenerator keysGen = new RSAKeysGenerator();
RSAKeysGenerator.RSAKeys keys = keysGen.generateKeys();
EncryptionAlgorithm genRsa = EncryptionAlgorithms.rsa()
    .publicKey(keys.getModulus(), keys.getPublicExponent())
    .privateKey(keys.getModulus(), keys.getPrivateExponent())
    .build();
```

**Custom Encryption Engines**
```java
// Custom engine for one specific algorithm
SymmetricEncryptionEngineFactory customFactory = ...; // your factory (for 1 engine)
EncryptionAlgorithm customAes = EncryptionAlgorithms.aes("secretPassphrase")
    .engineFactory(customFactory)
    .build();

// Custom set of factories (for all supported algorithms of EncryptionAlgorithms)
EncryptionEnginesFactories factories = ...; // your factories
EncryptionAlgorithms.defaultFactories(factories);
EncryptionAlgorithm customAes256 = EncryptionAlgorithms.aes256("secretPassphrase")
    // no need to set engineFactory as in previous example
    .build();
```

**Secure Properties**
```java
EncryptionAlgorithm algorithm = ...; // your algorithm
SecureProperties props = new SecureProperties(algorithm);
props.setProperty("plainProperty", "imGoodBoy");
props.setEncryptedProperty("encryptedProperty", "myDirtySecret");

props.store(...);
// plainProperty=imGoodBoy
// encryptedProperty=bf165faf5067...

// automatic decryption of values
String decrypted = props.getProperty("encryptedProperty"); // "myDirtySecret"
String original = props.getOriginalProperty("encryptedProperty"); // bf165...
```