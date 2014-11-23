package cz.d1x.crypto.encryption.crypto;

import cz.d1x.crypto.encryption.EncryptionException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Generator that can provide key pair for RSA encryption with 1024 key size.
 * This generator can be re-used for multiple key pair generations.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see RSA
 */
public class RSAKeysGenerator {

    private final KeyPairGenerator generator;

    /**
     * Creates a new generator of RSA keys.
     *
     * @throws EncryptionException possible exception when generation fail
     */
    public RSAKeysGenerator() throws EncryptionException {
        try {
            this.generator = KeyPairGenerator.getInstance("RSA");
            this.generator.initialize(1024);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Unable to generate RSA keys", e);
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
