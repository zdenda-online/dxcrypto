package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.ConcatCombineAlgorithm;
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

    private static final byte[] DEFAULT_KEY_SALT = new byte[]{0x27, 0x11, 0x65, 0x35,
            0x13, 0x77, 0x33, 0x21,
            0x40, 0x43, 0x18, 0x65};
    private static final int DEFAULT_KEY_HASH_ITERATIONS = 4096;

    private CryptoKeyFactory customKeyFactory;
    private byte[] keyPassword;
    private byte[] keySalt;
    private int keyHashIterations;
    private CombineAlgorithm combineAlgorithm;
    private String encoding;

    /**
     * Gets a name of algorithm supported by crypto.
     *
     * @return algorithm name
     */
    protected abstract String getAlgorithm();

    /**
     * Gets a short name of algorithm supported by crypto keys.
     *
     * @return algorithm name
     */
    protected abstract String getShortAlgorithm();

    /**
     * Gets size of the key.
     *
     * @return size of key
     */
    protected abstract int getKeySize();

    /**
     * Gets a block size of cipher (for CBC).
     *
     * @return cipher block size
     */
    protected abstract int getBlockSize();

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
     * Sets number of keyHashIterations of hashing for key derivation.
     * Recommended count is at least 1000.
     *
     * @param keyHashIterations number of keyHashIterations
     * @return this instance
     */
    public SymmetricAlgorithmBuilder keyHashIterations(int keyHashIterations) {
        this.keyHashIterations = keyHashIterations;
        return this;
    }

    /**
     * Sets algorithm combining IV and cipher text in output during encryption
     * and splitting from input during decryption.
     *
     * @param combineAlgorithm combine algorithm for IV and cipher text
     * @return this instance
     */
    public SymmetricAlgorithmBuilder combineAlgorithm(CombineAlgorithm combineAlgorithm) {
        this.combineAlgorithm = combineAlgorithm;
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
            encoding = Encoding.DEFAULT;
        }
        if (combineAlgorithm == null) {
            combineAlgorithm = new ConcatCombineAlgorithm(getBlockSize()); // default algorithm
        }

        CryptoKeyFactory keyFactory;
        if (customKeyFactory != null) {
            keyFactory = customKeyFactory;
        } else {
            if (keySalt == null) {
                keySalt = DEFAULT_KEY_SALT;
            }
            if (keyHashIterations == 0) {
                keyHashIterations = DEFAULT_KEY_HASH_ITERATIONS;
            }
            keyFactory = new PBKDF2KeyFactory(getShortAlgorithm(), keyPassword, getKeySize(), keySalt, keyHashIterations);
        }
        return new SymmetricAlgorithm(getAlgorithm(), keyFactory, combineAlgorithm, encoding);
    }
}
