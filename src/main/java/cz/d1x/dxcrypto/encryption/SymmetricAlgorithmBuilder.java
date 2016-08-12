package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.*;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParameters;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;

/**
 * Base builder for symmetric key algorithms based on {@link GenericEncryptionAlgorithm}.
 * For all supported symmetric ciphers we use initialization vector so we have it also in this builder even if
 * symmetric ciphers can be without IV by definition. If we would support other ciphers that does not have IV, this
 * builder should be refactored into two different classes.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see GenericEncryptionAlgorithm
 */
public final class SymmetricAlgorithmBuilder {

    private static final byte[] DEFAULT_KEY_SALT = new byte[]{0x27, 0x11, 0x65, 0x35,
            0x13, 0x77, 0x33, 0x21,
            0x40, 0x43, 0x18, 0x65};
    private static final int DEFAULT_KEY_HASH_ITERATIONS = 4096;

    private final EncryptionFactories factories;
    private final int keySize;
    private final int blockSize;

    // the key will be used from one of these, depending on what user uses as last call in this builder
    private EncryptionKeyFactory<ByteArray, DerivedKeyParameters> keyFactory = null;
    private byte[] key;
    private byte[] keyPassword;

    private SymmetricEncryptionEngineFactory<ByteArray> engineFactory;
    private byte[] keySalt = DEFAULT_KEY_SALT;
    private int keyHashIterations = DEFAULT_KEY_HASH_ITERATIONS;
    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;

    // initialize defaults in constructor!
    private ByteArrayFactory ivFactory;
    private CombiningSplitting ivOutputCombining;

    /**
     * Creates a new builder.
     *
     * @param factories     factories for engines
     * @param engineFactory factory for encryption engine
     * @param keySize       size of the key (in bits)
     * @param blockSize     size of the block (in bits)
     */
    public SymmetricAlgorithmBuilder(EncryptionFactories factories,
                                     SymmetricEncryptionEngineFactory<ByteArray> engineFactory,
                                     int keySize,
                                     int blockSize) {
        this.factories = factories;
        this.engineFactory = engineFactory;
        this.keySize = keySize;
        this.blockSize = blockSize / 8;

        this.ivOutputCombining = new ConcatAlgorithm(this.blockSize);
        this.ivFactory = new RandomByteArrayFactory();
    }

    /**
     * Sets factory for encryption engine.
     *
     * @param engineFactory factory for encryption engine
     * @return this instance
     * @throws IllegalArgumentException exception if passed factory is null
     */
    public SymmetricAlgorithmBuilder engineFactory(SymmetricEncryptionEngineFactory<ByteArray> engineFactory)
            throws IllegalArgumentException {
        if (engineFactory == null) throw new IllegalArgumentException("You must provide non-null engine factory!");
        this.engineFactory = engineFactory;
        return this;
    }

    /**
     * <p>
     * Set custom key. Note that client is responsible for correct key size.
     * If passed key size is invalid, {@link IllegalArgumentException} is thrown.
     * </p><p>
     * Note that if you use this method, it overrides previous setting of
     * {@link #keyFactory(EncryptionKeyFactory)} and {@link #keyPassword(byte[])}.
     * </p>
     *
     * @param key key to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed key is null or key size is invalid
     */
    public SymmetricAlgorithmBuilder key(byte[] key) throws IllegalArgumentException {
        if (key == null) throw new IllegalArgumentException("You must provide non-null key salt!");
        if (key.length != (keySize / 8))
            throw new IllegalArgumentException("Invalid key size, is " + key.length + " bytes but must be " + (keySize / 8) + "bytes");
        resetKeyFields(null, key, null);
        return this;
    }

    /**
     * <p>
     * Sets a key password for key derivation.
     * </p>
     * <p>
     * Note that if you use this method, it overrides previous setting of
     * {@link #keyFactory(EncryptionKeyFactory)} and {@link #key(byte[])}.
     * </p>
     *
     * @param keyPassword key password for key derivation
     * @return this instance
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public SymmetricAlgorithmBuilder keyPassword(byte[] keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        resetKeyFields(null, null, keyPassword);
        return this;
    }

    /**
     * <p>
     * Sets a key password for key derivation.
     * </p>
     * <p>
     * Note that if you use this method, it overrides previous setting of
     * {@link #keyFactory(EncryptionKeyFactory)} and {@link #key(byte[])}.
     * </p>
     *
     * @param keyPassword key password for key derivation
     * @return this instance
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public SymmetricAlgorithmBuilder keyPassword(String keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        return keyPassword(Encoding.getBytes(keyPassword));
    }

    /**
     * Sets salt for key derivation.
     * Recommended length is at least 8 bytes.
     *
     * @param keySalt salt to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed key salt is null
     */
    public SymmetricAlgorithmBuilder keySalt(byte[] keySalt) throws IllegalArgumentException {
        if (keySalt == null) throw new IllegalArgumentException("You must provide non-null key salt!");
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
    public SymmetricAlgorithmBuilder keySalt(String keySalt) throws IllegalArgumentException {
        if (keySalt == null) throw new IllegalArgumentException("You must provide non-null key salt!");
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
    public SymmetricAlgorithmBuilder keyHashIterations(int keyHashIterations) throws IllegalArgumentException {
        if (keyHashIterations < 1) throw new IllegalArgumentException("You must provide iterations >= 1!");
        this.keyHashIterations = keyHashIterations;
        return this;
    }

    /**
     * <p>
     * Sets all parameters for key derivation function.
     * </p>
     * <p>
     * Note that if you use this method, it overrides previous setting of
     * {@link #keyFactory(EncryptionKeyFactory)} and {@link #key(byte[])}.
     * </p>
     *
     * @param keyPassword key password for key derivation
     * @return this instance
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public SymmetricAlgorithmBuilder keyDerivation(byte[] keyPassword, byte[] keySalt,
                                                   int keyHashIterations) throws IllegalArgumentException {
        keyPassword(keyPassword);
        keySalt(keySalt);
        keyHashIterations(keyHashIterations);
        return this;
    }

    /**
     * <p>
     * Sets a custom key factory.
     * </p><p>
     * Note that if you use this method, it overrides previous setting of
     * {@link #key(byte[])} and {@link #keyPassword(byte[])}.
     * </p>
     *
     * @param keyFactory factory to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed factory is null
     */
    public SymmetricAlgorithmBuilder keyFactory(EncryptionKeyFactory<ByteArray, DerivedKeyParameters> keyFactory)
            throws IllegalArgumentException {
        if (keyFactory == null) throw new IllegalArgumentException("You must provide non-null key factory!");
        resetKeyFields(keyFactory, null, null);
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
    public SymmetricAlgorithmBuilder ivFactory(ByteArrayFactory ivFactory) throws IllegalArgumentException {
        if (ivFactory == null) throw new IllegalArgumentException("You must provide non-null ByteArrayFactory!");
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
    public SymmetricAlgorithmBuilder ivAndOutputCombining(CombiningSplitting ivOutputCombining) throws IllegalArgumentException {
        if (ivOutputCombining == null)
            throw new IllegalArgumentException("You must provide non-null CombiningSplitting!");
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
    public SymmetricAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) throws IllegalArgumentException {
        if (bytesRepresentation == null)
            throw new IllegalArgumentException("You must provide non-null BytesRepresentation!");
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
    public SymmetricAlgorithmBuilder encoding(String encoding) throws IllegalArgumentException {
        if (encoding == null) throw new IllegalArgumentException("You must provide non-null encoding!");
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
        return this;
    }

    /**
     * Builds a new instance of encryption algorithm.
     *
     * @return algorithm instance
     */
    public EncryptionAlgorithm build() throws IllegalArgumentException {
        DerivedKeyParameters keyParams = new DerivedKeyParameters(keyPassword, keySalt, keyHashIterations, keySize);
        ByteArray key = resolveKeyFactory().newKey(keyParams);
        EncryptionEngine engine = engineFactory.newEngine(key);
        return new GenericEncryptionAlgorithm(engine, bytesRepresentation, encoding, blockSize, ivFactory, ivOutputCombining);
    }

    private void resetKeyFields(EncryptionKeyFactory<ByteArray, DerivedKeyParameters> keyFactory, byte[] key, byte[] keyPassword) {
        this.keyFactory = keyFactory;
        this.key = key;
        this.keyPassword = keyPassword;
    }

    private EncryptionKeyFactory<ByteArray, DerivedKeyParameters> resolveKeyFactory() {
        // variant with custom key factory
        if (keyFactory != null) return keyFactory;

        // variant with custom key password, salt, hash iterations
        if (keyPassword != null && keyPassword.length != 0)
            return factories.derivedKeyFactory();

        // variant with custom key
        if (key != null && key.length != 0) {
            return new EncryptionKeyFactory<ByteArray, DerivedKeyParameters>() {
                @Override
                public ByteArray newKey(DerivedKeyParameters keyParams) throws EncryptionException {
                    return new ByteArray(key);
                }
            };
        }

        throw new IllegalArgumentException("Missing data for encryption key (at least one of these must be set: keyFactory, keyPassword, key)");
    }
}
