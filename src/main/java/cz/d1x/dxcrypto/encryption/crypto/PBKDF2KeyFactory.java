package cz.d1x.dxcrypto.encryption.crypto;

/**
 * Key factory that uses PBKDF2 function with HMAC-SHA1 for key derivation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class PBKDF2KeyFactory extends PBECryptoKeyFactory {

    /**
     * Creates a new PBKDF2 key factory.
     *
     * @param algorithm   name of encryption algorithm for which key will be generated
     * @param keyPassword password for key derivation
     * @param keyLength   length of desired key
     */
    public PBKDF2KeyFactory(String algorithm, byte[] keyPassword, int keyLength) {
        super(algorithm, keyPassword, keyLength);
    }

    /**
     * Creates a new PBKDF2 key factory.
     *
     * @param algorithm   name of encryption algorithm for which key will be generated
     * @param keyPassword password for key derivation
     * @param keySalt     salt for key derivation
     * @param keyLength   length of desired key
     */
    public PBKDF2KeyFactory(String algorithm, byte[] keyPassword, int keyLength, byte[] keySalt) {
        super(algorithm, keyPassword, keyLength, keySalt);
    }

    /**
     * Creates a new PBKDF2 key factory.
     *
     * @param algorithm       name of encryption algorithm for which key will be generated
     * @param keyPassword     password for key derivation
     * @param keySalt         salt for key derivation
     * @param iterationsCount count of iterations for key derivation
     * @param keyLength       length of desired key
     */
    public PBKDF2KeyFactory(String algorithm, byte[] keyPassword, int keyLength, byte[] keySalt, int iterationsCount) {
        super(algorithm, keyPassword, keyLength, keySalt, iterationsCount);
    }

    @Override
    protected String getAlgorithmName() {
        return "PBKDF2WithHmacSHA1";
    }
}
