package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.Encoding;

import java.security.Key;

/**
 * Factory that provides builders for available encryption algorithms.
 * Create a new builder and when you are done with parameters, call build()
 * to retrieve {@link EncryptionAlgorithm} instance.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithms {

    /**
     * Creates a new builder for AES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     * <p>
     * You can provide salt and iterations count for PBKDF2. If you want custom encryption key derivation, you can
     * use {@link #aes(KeyFactory)} method to specify custom factory for the key.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricCryptoAlgorithmBuilder aes(byte[] keyPassword) throws IllegalArgumentException {
        return new SymmetricCryptoAlgorithmBuilder(keyPassword, "AES/CBC/PKCS5Padding", "AES", 128, 16);
    }

    /**
     * Creates a new builder for AES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation</li>
     * </ul>
     * <p>
     * You can provide salt and iterations count for PBKDF2. If you want custom encryption key derivation, you can
     * use {@link #aes(KeyFactory)} method to specify custom factory for the key.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricCryptoAlgorithmBuilder aes(String keyPassword) throws IllegalArgumentException {
        return aes(Encoding.getBytes(keyPassword));
    }

    /**
     * Creates a new builder for AES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: based on given key factory</li>
     * </ul>
     *
     * @param keyFactory custom factory for encryption key
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key factory is null
     */
    public static SymmetricCryptoAlgorithmBuilder aes(KeyFactory<Key> keyFactory) throws IllegalArgumentException {
        return new SymmetricCryptoAlgorithmBuilder(keyFactory, "AES/CBC/PKCS5Padding", "AES", 16);
    }

    /**
     * Creates a new builder for 3DES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
     * </ul>
     * <p>
     * You can provide salt and iterations count for PBKDF2. If you want custom encryption key derivation, you can
     * use {@link #tripleDes(KeyFactory)} method to specify custom factory for the key.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricCryptoAlgorithmBuilder tripleDes(byte[] keyPassword) throws IllegalArgumentException {
        int keySize = (3 * 8) * 8; // crypto uses multiples of 24 (even 3DES uses 56 bytes keys)
        return new SymmetricCryptoAlgorithmBuilder(keyPassword, "DESede/CBC/PKCS5Padding", "DESede", keySize, 8);
    }

    /**
     * Creates a new builder for 3DES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: PBKDF2 with HMAC-SHA1 for key derivation (can be overridden)</li>
     * </ul>
     * <p>
     * You can provide salt and iterations count for PBKDF2. If you want custom encryption key derivation, you can
     * use {@link #tripleDes(KeyFactory)} method to specify custom factory for the key.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricCryptoAlgorithmBuilder tripleDes(String keyPassword) throws IllegalArgumentException {
        return tripleDes(Encoding.getBytes(keyPassword));
    }

    /**
     * Crates a new builder for 3DES encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Symmetric</li>
     * <li>Operation mode: Cipher Block Chaining (CBC)</li>
     * <li>Input padding: PKCS#5</li>
     * <li>Encryption key: based on given key factory</li>
     * </ul>
     *
     * @param keyFactory custom factory for encryption key
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key factory is null
     */
    public static SymmetricCryptoAlgorithmBuilder tripleDes(KeyFactory<Key> keyFactory) throws IllegalArgumentException {
        return new SymmetricCryptoAlgorithmBuilder(keyFactory, "DESede/CBC/PKCS5Padding", "DESede", 8);
    }

    /**
     * Creates a new builder for RSA encryption algorithm with these properties:
     * <ul>
     * <li>Type of cipher: Asymmetric</li>
     * <li>Operation mode: Electronic Codebook (ECB)</li>
     * <li>Input padding: OAEP with SHA-256 (MGF1 for masks)</li>
     * </ul>
     * If you don't have key pair, you can generate some via {@link RSAKeysGenerator}.
     *
     * @return builder for RSA encryption algorithm
     */
    public static AsymmetricCryptoAlgorithmBuilder rsa() {
        return new AsymmetricCryptoAlgorithmBuilder("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
