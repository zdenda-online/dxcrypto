package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.encryption.crypto.AESBuilder;
import cz.d1x.dxcrypto.encryption.crypto.CryptoKeyFactory;
import cz.d1x.dxcrypto.encryption.crypto.RSABuilder;
import cz.d1x.dxcrypto.encryption.crypto.TripleDESBuilder;

/**
 * Factory that provides builders for available encryption algorithms.
 * Create a new builder and when you are done with parameters, call {@link EncryptionAlgorithmBuilder#build()}
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithms {

    /**
     * Creates a new builder for AES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public static AESBuilder aes(byte[] keyPassword) {
        return new AESBuilder(keyPassword);
    }

    /**
     * Creates a new builder for AES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public static AESBuilder aes(String keyPassword) {
        return new AESBuilder(keyPassword);
    }

    /**
     * Crates a new builder for AES encryption algorithm.
     * Use this if you want override default PBKDF2 for key derivation.
     *
     * @param customKeyFactory custom factory for encryption key
     */
    public static AESBuilder aes(CryptoKeyFactory customKeyFactory) {
        return new AESBuilder(customKeyFactory);
    }

    /**
     * Creates a new builder for 3DES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public static TripleDESBuilder tripleDes(byte[] keyPassword) {
        return new TripleDESBuilder(keyPassword);
    }

    /**
     * Creates a new builder for 3DES encryption algorithm.
     *
     * @param keyPassword password for key derivation
     */
    public static TripleDESBuilder tripleDes(String keyPassword) {
        return new TripleDESBuilder(keyPassword);
    }

    /**
     * Crates a new builder for 3DES encryption algorithm.
     * Use this constructor if you want override default PBKDF2 for key derivation.
     *
     * @param customKeyFactory custom factory for encryption key
     */
    public static TripleDESBuilder tripleDes(CryptoKeyFactory customKeyFactory) {
        return new TripleDESBuilder(customKeyFactory);
    }

    /**
     * Creates a new builder for RSA encryption algorithm.
     */
    public static RSABuilder rsa() {
        return new RSABuilder();
    }
}
