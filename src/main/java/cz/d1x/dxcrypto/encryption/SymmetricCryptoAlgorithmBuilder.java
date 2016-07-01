package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.*;

import java.security.Key;

/**
 * Base builder for symmetric key algorithms based on {@link SymmetricCryptoAlgorithm}.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricCryptoAlgorithm
 */
public final class SymmetricCryptoAlgorithmBuilder {

    private static final byte[] DEFAULT_KEY_SALT = new byte[]{0x27, 0x11, 0x65, 0x35,
            0x13, 0x77, 0x33, 0x21,
            0x40, 0x43, 0x18, 0x65};
    private static final int DEFAULT_KEY_HASH_ITERATIONS = 4096;

    private final String algorithmName;
    private final String shortAlgorithmName;
    private final int keySize;

    // one these must be set via constructor
    private final KeyFactory<Key> keyFactory;
    private final byte[] keyPassword;

    private byte[] keySalt = DEFAULT_KEY_SALT;
    private int keyHashIterations = DEFAULT_KEY_HASH_ITERATIONS;
    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;
    private ByteArrayFactory ivFactory = new RandomByteArrayFactory();
    private CombiningSplitting ivOutputCombining; // initialize default in constructor!

    /**
     * Creates a new builder.
     *
     * @param keyPassword        key password
     * @param algorithmName      full algorithm name (used for Cipher initialization)
     * @param shortAlgorithmName short algorithm name (typically only first part of full name)
     * @param keySize            size of the key (in bits)
     * @param blockSize          size of the block (in bits)
     */
    public SymmetricCryptoAlgorithmBuilder(byte[] keyPassword,
                                           String algorithmName, String shortAlgorithmName,
                                           int keySize, int blockSize) {
        if (keyPassword == null) {
            throw new IllegalArgumentException("You must provide non-null key password!");
        }
        this.keyPassword = keyPassword;
        this.keySize = keySize;
        this.keyFactory = null;

        this.algorithmName = algorithmName;
        this.shortAlgorithmName = shortAlgorithmName;
        this.ivOutputCombining = new ConcatAlgorithm(blockSize / 8);
    }

    /**
     * Creates a new builder.
     *
     * @param keyFactory         factory for the keys
     * @param algorithmName      full algorithm name (used for Cipher initialization)
     * @param shortAlgorithmName short algorithm name (typically only first part of full name)
     * @param blockSize          size of the block (in bits)
     */
    public SymmetricCryptoAlgorithmBuilder(KeyFactory<Key> keyFactory,
                                           String algorithmName, String shortAlgorithmName,
                                           int blockSize) {
        if (keyFactory == null) {
            throw new IllegalArgumentException("You must provide non-null key factory!");
        }
        this.keyPassword = null;
        this.keySize = -1;
        this.keyFactory = keyFactory;

        this.algorithmName = algorithmName;
        this.shortAlgorithmName = shortAlgorithmName;
        this.ivOutputCombining = new ConcatAlgorithm(blockSize / 8);
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed key salt is null
     */
    public SymmetricCryptoAlgorithmBuilder keySalt(byte[] keySalt) throws IllegalArgumentException {
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
    public SymmetricCryptoAlgorithmBuilder keySalt(String keySalt) throws IllegalArgumentException {
        checkKeyFactory();
        if (keySalt == null) {
            throw new IllegalArgumentException("You must provide non-null key salt!");
        }
        return keySalt(Encoding.getBytes(keySalt));
    }

    /**
     * Sets number of iterations of hashing for key derivation.
     * Recommended count is at least 1000.
     *
     * @param keyHashIterations number of keyHashIterations
     * @return this instance
     * @throws IllegalArgumentException exception if passed iterations are lower than 1
     */
    public SymmetricCryptoAlgorithmBuilder keyHashIterations(int keyHashIterations) throws IllegalArgumentException {
        checkKeyFactory();
        if (keyHashIterations < 1) {
            throw new IllegalArgumentException("You must provide iterations for key hashing >= 1!");
        }
        this.keyHashIterations = keyHashIterations;
        return this;
    }

    /**
     * Sets algorithm for generation of initialization vector for every message.
     * This is used only for algorithms that use it (typically CBC-based algorithms like AES, 3DES...).
     * Note that it is recommended to have unique initialization vector for every message that is later combined with
     * encrypted output via {@link #ivAndOutputCombining(CombiningSplitting)} into the final output.
     *
     * @param ivFactory factory for initialization vector
     * @return this instance
     * @throws IllegalArgumentException exception if passed ByteArrayFactory is null
     */
    public SymmetricCryptoAlgorithmBuilder ivFactory(ByteArrayFactory ivFactory) throws IllegalArgumentException {
        if (ivFactory == null) {
            throw new IllegalArgumentException("You must provide non-null ByteArrayFactory!");
        }
        this.ivFactory = ivFactory;
        return this;
    }

    /**
     * Sets algorithm combining initialization vector and cipher text in output during encryption
     * and splitting from input during decryption.
     *
     * @param ivOutputCombining combine/split algorithm for IV and cipher text
     * @return this instance
     * @throws IllegalArgumentException exception if passed CombiningSplitting is null
     */
    public SymmetricCryptoAlgorithmBuilder ivAndOutputCombining(CombiningSplitting ivOutputCombining) throws IllegalArgumentException {
        if (ivOutputCombining == null) {
            throw new IllegalArgumentException("You must provide non-null CombiningSplitting!");
        }
        this.ivOutputCombining = ivOutputCombining;
        return this;
    }

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     * @throws IllegalArgumentException exception if passed BytesRepresentation is null
     */
    public SymmetricCryptoAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) throws IllegalArgumentException {
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
    public SymmetricCryptoAlgorithmBuilder encoding(String encoding) throws IllegalArgumentException {
        if (encoding == null) {
            throw new IllegalArgumentException("You must provide non-null encoding!");
        }
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
        return this;
    }

    private void checkKeyFactory() throws IllegalArgumentException {
        if (keyFactory != null) {
            throw new IllegalArgumentException("You initialized builder with custom key factory. It is not allowed " +
                    "to use key salt or hash iterations (it wouldn't be used anyway)");
        }
    }

    /**
     * Builds a new instance of encryption algorithm.
     *
     * @return algorithm instance
     */
    public EncryptionAlgorithm build() throws IllegalArgumentException {
        KeyFactory<Key> kf;
        if (keyFactory != null) {
            kf = keyFactory;
        } else {
            kf = new PBKDF2KeyFactory(shortAlgorithmName, keyPassword, keySize, keySalt, keyHashIterations);
        }
        return new SymmetricCryptoAlgorithm(algorithmName, kf, ivFactory, ivOutputCombining, bytesRepresentation, encoding);
    }
}
