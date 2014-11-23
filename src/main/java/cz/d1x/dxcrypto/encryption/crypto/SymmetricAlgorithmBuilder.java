package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithmBuilder;
import cz.d1x.dxcrypto.encryption.EncryptionException;

/**
 * Base builder for symmetric key algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricAlgorithm
 */
public abstract class SymmetricAlgorithmBuilder implements EncryptionAlgorithmBuilder {

    private static final byte[] DEFAULT_SALT = new byte[]{0x27, 0x11, 0x65, 0x35,
            0x13, 0x77, 0x33, 0x21,
            0x40, 0x43, 0x18, 0x65};
    private static final int DEFAULT_ITERATIONS = 4096;

    private CryptoKeyFactory customKeyFactory;
    private byte[] keyPassword;
    private byte[] keySalt;
    private int iterations;
    private String encoding;

    protected abstract String getAlgorithm();

    protected abstract String getShortAlgorithm();

    protected abstract int getKeySize();

    protected SymmetricAlgorithmBuilder(byte[] keyPassword) {
        this.keyPassword = keyPassword;
    }

    protected SymmetricAlgorithmBuilder(String keyPassword) {
        this.keyPassword = Encoding.getBytes(keyPassword);
    }

    protected SymmetricAlgorithmBuilder(CryptoKeyFactory customKeyFactory) {
        this.customKeyFactory = customKeyFactory;
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     */
    public SymmetricAlgorithmBuilder keySalt(byte[] keySalt) {
        this.keySalt = keySalt;
        return this;
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     */
    public SymmetricAlgorithmBuilder keySalt(String keySalt) {
        this.keySalt = Encoding.getBytes(keySalt);
        return this;
    }

    /**
     * Sets number of iterations of hashing for key derivation.
     * Recommended count is at least 1000.
     *
     * @param iterations number of iterations
     * @return this instance
     */
    public SymmetricAlgorithmBuilder hashingIterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    /**
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     */
    public SymmetricAlgorithmBuilder encoding(String encoding) {
        this.encoding = encoding;
        return this;
    }

    @Override
    public EncryptionAlgorithm build() throws EncryptionException {
        if (encoding == null) {
            encoding = Encoding.UTF_8;
        }

        CryptoKeyFactory keyFactory;
        if (customKeyFactory != null) {
            keyFactory = customKeyFactory;
        } else {
            if (keySalt == null) {
                keySalt = DEFAULT_SALT;
            }
            if (iterations == 0) {
                iterations = DEFAULT_ITERATIONS;
            }
            keyFactory = new PBKDF2KeyFactory(getShortAlgorithm(), keyPassword, getKeySize(), keySalt, iterations);
        }
        return new SymmetricAlgorithm(getAlgorithm(), keyFactory, encoding);
    }
}
