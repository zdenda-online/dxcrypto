DXCrypto: Easy Java Cryptography
================================
Simple Java library for cryptography (hashing and encryption).

The core implementation is built purely on Java SE without any dependencies.
Most of times, it one should be sufficient for you. But if you need it, there is also version of this library
that uses Bouncy Castle (typically if you want AES-256 without JCE installed).

I created this library because I was tired of object initializations of existing Java APIs and all those checked
exceptions it uses. It often happens that programmers using Java encryption APIs (from *java.security* and
*javax.crypto* packages) consume a lot of time trying to initialize their algorithms properly. The aim of this library
is to ease this pain as well as providing best practices in their usage (see features list below).

This library does **not** contain any custom implementation of encryption algorithms. The core uses existing Java APIs
implementations, in bc version uses Bouncy Castle. On the other hand, it is also easily extensible in many ways.
It also provides few utility classes like SecureProperties that extend existing *java.util.Properties* with
encrypted properties.

This library is distributed under MIT license in the hope that it will be useful, but without any warranty.
If you find any issue, please contact me on my e-mail.

Maven dependencies
------------------
The core implementation (using built-in Java APIs)
```xml
<dependency>
   <groupId>cz.d1x</groupId>
   <artifactId>dxcrypto-core</artifactId>
   <version>2.0</version>
</dependency>
```

The Bouncy Castle implementation
```xml
<dependency>
   <groupId>cz.d1x</groupId>
   <artifactId>dxcrypto-bc</artifactId>
   <version>2.0</version>
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
into the output (so two same inputs always have different output which strengthens security).

- Asymmetric encryption algorithm **RSA** with ECB and OAEP padding

- **SecureProperties** that extend *java.util.Properties* by adding possibility to store/read encrypted values

Examples
--------
**Hashing**
```java
HashingAlgorithm sha256 = HashingAlgorithms.sha256()
                .build();

// byte[] or String based methods
byte[] hashedBytes = sha256.hash(new byte[]{'h', 'e', 'l', 'l', 'o'});
String hashedString = sha256.hash("hello"); // 2cf24dba5fb0a...

// customization of hashing function
HashingAlgorithm customizedSha512 = HashingAlgorithms.sha512()
        .encoding("UTF-8") // optional, defaults to UTF-8
        .bytesRepresentation(new HexRepresentation(true)) // optional, defaults to lower-cased HEX
        .repeated(27) // optional, defaults to no repeating
        .build();

// salting (with default combining of input text and salt)
SaltedHashingAlgorithm saltedSha1 = HashingAlgorithms.sha1()
        .salted()
        .build();
String salted = saltedSha1.hash("your input text", "your salt");

// salting with custom combining of input text and salt
Combining combining = new ConcatAlgorithm(); // you can implement your custom combining
SaltedHashingAlgorithm customSaltedSha256 = HashingAlgorithms.sha256()
        .salted(combining)
        .build();
```

**Symmetric Encryption**
```java
// AES with PBKDF2 key derivation from given password
EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secretPassword")
        .build();

// byte[] or String based methods
byte[] encryptedBytes = aes.encrypt(new byte[]{'h', 'e', 'l', 'l', 'o'});
byte[] decryptedBytes = aes.decrypt(encryptedBytes);
String encryptedString = aes.encrypt("hello");
String decryptedString = aes.decrypt(encryptedString);

// customization of symmetric encryption algorithm with PBKDF2
EncryptionAlgorithm customizedAes = EncryptionAlgorithms.aes("secretPassphrase")
        .keySalt("saltForKeyDerivation") // optional, salt for key derivation
        .keyHashIterations(4096) // optional, hash iterations for key derivation
        .ivAndOutputCombining(new ConcatAlgorithm()) // optional, combining IV and output
        .bytesRepresentation(new HexRepresentation(true)) // optional, how to represent bytes
        .build();

// custom AES key (without key derivation function)
byte[] key = new byte[16]; // your key (somehow filled), must have correct size for algorithm!
EncryptionAlgorithm customKeyAes = EncryptionAlgorithms.aes()
        .key(key)
        .build();
```

**Asymmetric Encryption**
```java
BigInteger modulus = BigInteger.ONE; // your modulus (n)
BigInteger publicExponent = BigInteger.ONE; // your public exponent (e)
BigInteger privateExponent = BigInteger.ONE; // your private exponent (d)
EncryptionAlgorithm rsa = EncryptionAlgorithms.rsa()
        .publicKey(modulus, publicExponent)
        .privateKey(modulus, privateExponent)
        .build();

// generated keys
RSAKeysGenerator keysGen = new RSAKeysGenerator(); // you can specify key size (defaults 1024)
RSAKeyParams[] keys = keysGen.generateKeys();
EncryptionAlgorithm genRsa = EncryptionAlgorithms.rsa()
        .publicKey(keys[0].getModulus(), keys[0].getExponent())
        .privateKey(keys[1].getModulus(), keys[1].getExponent())
        .build();
```

**Bouncy Castle Encryption**
```java
// switching to all encryption algorithms to bouncy castle
BouncyCastleFactories bcFactories = new BouncyCastleFactories();
EncryptionAlgorithms.defaultFactories(bcFactories);

// now build algorithms the same way as before
EncryptionAlgorithm bcAes = EncryptionAlgorithms.aes("secretPassphrase")
        .build();

// using bouncy castle only for one specific algorithm
EncryptionAlgorithms.defaultFactories(new CryptoFactories()); // back to default
EncryptionAlgorithms.aes256("secretPassphrase")
        .keyFactory(bcFactories.derivedKeyFactory()) // optional, default will work as well
        .engineFactory(bcFactories.aes256()) // be sure to use correct factory
        .build();
```

**Custom Encryption Engines**
```java
// Custom factory for one specific algorithm
SymmetricEncryptionEngineFactory<ByteArray> customFactory = null; // your implementation
EncryptionAlgorithm customAes = EncryptionAlgorithms.aes("secretPassphrase")
        .engineFactory(customFactory)
        .build();

// Global configuration for all factories
EncryptionFactories factories = null; // your implementation of all factories
EncryptionAlgorithms.defaultFactories(factories);
EncryptionAlgorithm customAes256 = EncryptionAlgorithms.aes256("secretPassphrase")
         // no need to set engineFactory as they are globally set now
         .build();
```

**Secure Properties**
```java
EncryptionAlgorithm algorithm = ...; // your algorithm
SecureProperties props = new SecureProperties(algorithm);
props.setProperty("plainProperty", "imGoodBoy");
props.setEncryptedProperty("encryptedProperty", "myDirtySecret");

// props.store(...);
// plainProperty=imGoodBoy
// encryptedProperty=bf165faf5067...

// automatic decryption of values
String decrypted = props.getProperty("encryptedProperty"); // "myDirtySecret"
String original = props.getOriginalProperty("encryptedProperty"); // bf165...
```
