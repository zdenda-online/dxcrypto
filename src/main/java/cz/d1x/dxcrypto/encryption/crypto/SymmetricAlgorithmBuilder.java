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
     *
     * @param keySalt salt to be set
     * @return this instance
     */
    public SymmetricAlgorithmBuilder keySalt(String keySalt) {
        this.keySalt = Encoding.getBytes(keySalt);
        return this;
    }

    /**
     * Sets number of iterations for key derivation.
     *
     * @param iterations number of iterations
     * @return this instance
     */
    public SymmetricAlgorithmBuilder iterations(int iterations) {
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
                keySalt = new byte['0']; // default salt
            }
            if (iterations == 0) {
                iterations = 1; // default iterations
            }
            keyFactory = new PBKDF2KeyFactory(getShortAlgorithm(), keyPassword, getKeySize(), keySalt, iterations);
        }
        return new SymmetricAlgorithm(getAlgorithm(), keyFactory, encoding);
    }
}
