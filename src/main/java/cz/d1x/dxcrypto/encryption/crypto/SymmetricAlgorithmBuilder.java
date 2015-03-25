package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.*;
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
    private byte[] keySalt = DEFAULT_KEY_SALT;
    private int keyHashIterations = DEFAULT_KEY_HASH_ITERATIONS;
    private CombineSplitAlgorithm combineSplitAlgorithm = new ConcatAlgorithm(getBlockSize());
    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;

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
        if (keyPassword == null) {
            throw new IllegalArgumentException("You must provide non-null key password!");
        }
        this.keyPassword = keyPassword;
    }

    protected SymmetricAlgorithmBuilder(String keyPassword) {
        if (keyPassword == null) {
            throw new IllegalArgumentException("You must provide non-null key password!");
        }
        this.keyPassword = Encoding.getBytes(keyPassword);
    }

    protected SymmetricAlgorithmBuilder(CryptoKeyFactory customKeyFactory) {
        if (customKeyFactory == null) {
            throw new IllegalArgumentException("You must provide non-null key factory!");
        }
        this.customKeyFactory = customKeyFactory;
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed key salt is null
     */
    public SymmetricAlgorithmBuilder keySalt(byte[] keySalt) {
        if (keySalt == null) {
            throw new IllegalArgumentException("You must provide non-null key salt!");
        }
        this.keySalt = keySalt;
        return this;
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed key salt is null
     */
    public SymmetricAlgorithmBuilder keySalt(String keySalt) {
        if (keySalt == null) {
            throw new IllegalArgumentException("You must provide non-null key salt!");
        }
        return keySalt(Encoding.getBytes(keySalt));
    }

    /**
     * Sets number of keyHashIterations of hashing for key derivation.
     * Recommended count is at least 1000.
     *
     * @param keyHashIterations number of keyHashIterations
     * @return this instance
     * @throws IllegalArgumentException exception if passed iterations are lower than 1
     */
    public SymmetricAlgorithmBuilder keyHashIterations(int keyHashIterations) {
        if (keyHashIterations < 1) {
            throw new IllegalArgumentException("You must provide iterations for key hashing >= 1!");
        }
        this.keyHashIterations = keyHashIterations;
        return this;
    }

    /**
     * Sets algorithm combining IV and cipher text in output during encryption
     * and splitting from input during decryption.
     *
     * @param combineSplitAlgorithm combine/split algorithm for IV and cipher text
     * @return this instance
     * @throws IllegalArgumentException exception if passed CombineSplitAlgorithm is null
     */
    public SymmetricAlgorithmBuilder combineSplitAlgorithm(CombineSplitAlgorithm combineSplitAlgorithm) {
        if (combineSplitAlgorithm == null) {
            throw new IllegalArgumentException("You must provide non-null CombineSplitAlgorithm!");
        }
        this.combineSplitAlgorithm = combineSplitAlgorithm;
        return this;
    }

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     * @throws IllegalArgumentException exception if passed BytesRepresentation is null
     */
    public SymmetricAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) {
        if (bytesRepresentation == null) {
            throw new IllegalArgumentException("You must provide non-null BytesRepresentation!");
        }
        this.bytesRepresentation = bytesRepresentation;
        return this;
    }

    /**
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     * @throws IllegalArgumentException exception if given encoding is null or not supported
     */
    public SymmetricAlgorithmBuilder encoding(String encoding) {
        if (encoding == null) {
            throw new IllegalArgumentException("You must provide non-null encoding!");
        }
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
        return this;
    }

    @Override
    public EncryptionAlgorithm build() throws EncryptionException {
        CryptoKeyFactory keyFactory;
        if (customKeyFactory != null) {
            keyFactory = customKeyFactory;
        } else {
            keyFactory = new PBKDF2KeyFactory(getShortAlgorithm(), keyPassword, getKeySize(), keySalt, keyHashIterations);
        }
        return new SymmetricAlgorithm(getAlgorithm(), keyFactory, combineSplitAlgorithm, bytesRepresentation, encoding);
    }
}
