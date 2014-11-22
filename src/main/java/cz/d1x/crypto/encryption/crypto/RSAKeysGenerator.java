package cz.d1x.crypto.encryption.crypto;

import cz.d1x.crypto.encryption.EncryptionException;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Generator that can provide key pair for RSA encryption.
 * Due to security reasons, generator cannot be re-used for key generation, you must create a new instance
 * if you need a new key pair.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see RSA
 */
public class RSAKeysGenerator {

    private final KeyPair keyPair;

    /**
     * Creates a new generator of RSA keys.
     *
     * @throws EncryptionException possible exception when generation fail
     */
    public RSAKeysGenerator() throws EncryptionException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            this.keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Unable to generate RSA keys", e);
        }
    }

    /**
     * Gets generated RSA key pair.
     *
     * @return generated RSA key pair
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * Gets a factory for public key of RSA.
     *
     * @return factory for public key
     */
    public CryptoKeyFactory getPublicKeyFactory() {
        return new CryptoKeyFactory() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPublic();
            }
        };
    }

    /**
     * Gets a factory for private key of RSA.
     *
     * @return factory for private key
     */
    public CryptoKeyFactory getPrivateKeyFactory() {
        return new CryptoKeyFactory() {
            @Override
            public Key getKey() throws EncryptionException {
                return keyPair.getPrivate();
            }
        };
    }
}
