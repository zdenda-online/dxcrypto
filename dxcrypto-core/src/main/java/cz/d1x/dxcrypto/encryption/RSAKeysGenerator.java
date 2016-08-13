package cz.d1x.dxcrypto.encryption;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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
     * Generates a new RSA keys - its modulus, public and private exponents.
     *
     * @return RSA keys
     */
    public RSAKeys generateKeys() {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKeys(publicKey.getModulus(), publicKey.getPublicExponent(), privateKey.getPrivateExponent());
    }

    /**
     * Generates a new {@link KeyPair} for RSA.
     *
     * @return RSA key pair
     */
    public KeyPair generateKeyPair() {
        return generator.generateKeyPair();
    }


    public static class RSAKeys {
        private final BigInteger modulus;
        private final BigInteger publicExponent;
        private final BigInteger privateExponent;

        public RSAKeys(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
            this.privateExponent = privateExponent;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        public BigInteger getPublicExponent() {
            return publicExponent;
        }

        public BigInteger getPrivateExponent() {
            return privateExponent;
        }
    }
}
