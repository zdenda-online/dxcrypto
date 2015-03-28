package cz.d1x.dxcrypto.encryption;

import java.security.Key;

/**
 * Key factory that uses PBKDF2 function with HMAC-SHA1 for key derivation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class PBKDF2KeyFactory implements KeyFactory<Key> {

    private final PBEKeyFactory keyFactory;

    /**
     * Creates a new PBKDF2 key factory.
     *
     * @param encryptionAlgorithmName       name of encryption algorithm for which key will be generated
     * @param keyPassword     password for key derivation
     * @param keySalt         salt for key derivation
     * @param iterationsCount count of iterations for key derivation
     * @param keyLength       length of desired key
     */
    protected PBKDF2KeyFactory(String encryptionAlgorithmName, byte[] keyPassword, int keyLength, byte[] keySalt, int iterationsCount) {
        this.keyFactory = new PBEKeyFactory(encryptionAlgorithmName, "PBKDF2WithHmacSHA1",
                keyPassword, keyLength, keySalt, iterationsCount);
    }

    @Override
    public Key getKey() throws EncryptionException {
        return keyFactory.getKey();
    }
}
