package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.crypto.RSACryptoEngineFactory;
import cz.d1x.dxcrypto.encryption.crypto.SymmetricCryptoEngineFactory;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 * Factory that provides builders for available encryption algorithms.
 * Create a new builder and when you are done with parameters, call build()
 * to retrieve {@link EncryptionAlgorithm} instance.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithms {

    /**
     * <p>
     * Creates a new builder for AES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 128 bits</li>
     * <li>Block size: 128 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(byte[] keyPassword) throws IllegalArgumentException {
        SymmetricEncryptionEngineFactory engineFactory = new SymmetricCryptoEngineFactory("AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, 128, 128);
    }

    /**
     * <p>
     * Creates a new builder for AES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 128 bits</li>
     * <li>Block size: 128 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(String keyPassword) throws IllegalArgumentException {
        return aes(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for AES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 256 bits</li>
     * <li>Block size: 128 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     * <p>
     * Note that if you use default javax.crypto implementation, you may need JCE installed for AES-256.
     * On the other hand, you can use custom {@link EncryptionEngine}, e.g. Bouncy Castle that does need JCE.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(byte[] keyPassword) throws IllegalArgumentException {
        SymmetricEncryptionEngineFactory engineFactory = new SymmetricCryptoEngineFactory("AES/CBC/PKCS7Padding", "PBKDF2WithHmacSHA1");
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, 256, 128);
    }

    /**
     * <p>
     * Creates a new builder for AES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 256 bits</li>
     * <li>Block size: 128 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     * <p>
     * Note that if you use default javax.crypto implementation, you may need JCE installed for AES-256.
     * On the other hand, you can use custom {@link EncryptionEngine}, e.g. Bouncy Castle that does need JCE.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(String keyPassword) throws IllegalArgumentException {
        return aes256(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for 3DES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 192 bits</li>
     * <li>Block size: 64 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
     * </ul>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(byte[] keyPassword) throws IllegalArgumentException {
        int keySize = (3 * 8) * 8; // crypto uses multiples of 24 (even 3DES uses 56 bytes keys)
        SymmetricEncryptionEngineFactory engineFactory = new SymmetricCryptoEngineFactory("DESede/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, keySize, 64);
    }

    /**
     * <p>
     * Creates a new builder for 3DES encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link SymmetricEncryptionEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Key size: 192 bits</li>
     * <li>Block size: 64 bits</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
     * </ul>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(String keyPassword) throws IllegalArgumentException {
        return tripleDes(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for RSA encryption algorithm that uses standard Java API implementation (javax.crypto) as
     * default encryption engine.
     * Note that you may use custom {@link RSAEngineFactory} to bypass your custom engine.
     * </p><p>
     * Properties of default engine from Java API implementation:
     * </p>
     * <ul>
     * <li>Type of cipher: Asymmetric</li>
     * <li>Operation mode: Electronic Codebook (ECB)</li>
     * <li>Input padding: OAEP with SHA-256 (MGF1 for masks)</li>
     * </ul>
     * If you don't have key pair, you can generate some via {@link RSAKeysGenerator}.
     *
     * @return builder for RSA encryption algorithm
     */
    public static RSAAlgorithmBuilder rsa() {
        RSACryptoEngineFactory factory = new RSACryptoEngineFactory("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        return new RSAAlgorithmBuilder(factory);
    }

    /**
     * Checks whether Java Cryptography Extension (JCE) is installed. Thus stronger ciphers (e.g. AES-256 can be used).
     *
     * @return true if JCE is installed, otherwise false
     */
    public static boolean isJceInstalled() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES") == Integer.MAX_VALUE;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
