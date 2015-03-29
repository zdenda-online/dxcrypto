package cz.d1x.dxcrypto.encryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * <p>
 * Generator that can provide key pair for RSA encryption.
 * This generator can be re-used for multiple key pair generations.
 * </p><p>
 * This class is immutable and can be considered thread safe.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class RSAKeysGenerator {

    private static final int DEFAULT_KEY_SIZE = 1024;

    private final KeyPairGenerator generator;

    /**
     * Creates a new generator of RSA keys with default 1024 size of the key.
     */
    public RSAKeysGenerator() {
        this(DEFAULT_KEY_SIZE);
    }

    /**
     * Creates a new generator of RSA keys with given key size.
     *
     * @param keySize size of the key
     */
    public RSAKeysGenerator(int keySize) throws EncryptionException {
        try {
            this.generator = KeyPairGenerator.getInstance("RSA");
            this.generator.initialize(keySize);
        } catch (NoSuchAlgorithmException e) {
            // this should not happen, it wou
            throw new EncryptionException("Unable to initialize RSA keys generator, is it supported by your JRE?", e);
        }
    }

    /**
     * Generates a new key pair for RSA.
     *
     * @return RSA key pair
     */
    public KeyPair generateKeys() {
        return generator.generateKeyPair();
    }
}
