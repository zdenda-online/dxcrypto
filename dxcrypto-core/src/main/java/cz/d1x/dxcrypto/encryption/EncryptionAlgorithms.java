package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.crypto.CryptoFactories;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;

/**
 * Factory that provides builders for available encryption algorithms.
 * Create a new builder and when you are done with parameters, call build()
 * to retrieve {@link EncryptionAlgorithm} instance.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithms {

    private static EncryptionFactories defaultFactories = new CryptoFactories();

    /**
     * Sets a new global factories for encryption engines.
     * It defaults to {@link CryptoFactories}.
     *
     * @param factories factories to be set
     */
    public static void defaultFactories(EncryptionFactories factories) {
        if (factories == null) throw new IllegalArgumentException("You must provide non-null engine factories!");
        EncryptionAlgorithms.defaultFactories = factories;
    }

    /**
     * <p>
     * Creates a new builder for AES (128b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(byte[] keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.aes();
        SymmetricAlgorithmBuilder builder = new SymmetricAlgorithmBuilder(defaultFactories, engineFactory, 128, 128);
        return builder.keyPassword(keyPassword);
    }

    /**
     * <p>
     * Creates a new builder for AES (128b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(String keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        return aes(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for AES (128b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p><p>
     * Note that during build process, you must call one of methods for specifying encryption key.
     * The methods are</p>
     * <ul>
     * <li>{@link SymmetricAlgorithmBuilder#keyPassword(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#key(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#keyFactory(EncryptionKeyFactory)}</li>
     * </ul>
     *
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes() {
        return aes(new byte[0]);
    }

    /**
     * <p>
     * Creates a new builder for AES (256b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p><p>
     * Note that if you use default {@link CryptoFactories}, you may need JCE installed for AES-256.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(byte[] keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.aes256();
        SymmetricAlgorithmBuilder builder = new SymmetricAlgorithmBuilder(defaultFactories, engineFactory, 256, 128);
        return builder.keyPassword(keyPassword);
    }

    /**
     * <p>
     * Creates a new builder for AES (256b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms) .
     * </p><p>
     * Note that if you use default {@link CryptoFactories}, you may need JCE installed for AES-256.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(String keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        return aes256(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for AES (256b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p><p>
     * Note that during build process, you must call one of methods for specifying encryption key.
     * The methods are</p>
     * <ul>
     * <li>{@link SymmetricAlgorithmBuilder#keyPassword(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#key(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#keyFactory(EncryptionKeyFactory)}</li>
     * </ul>
     *
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256() {
        return aes256(new byte[0]);
    }

    /**
     * <p>
     * Creates a new builder for 3DES encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(byte[] keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        int keySize = (3 * 8) * 8; // crypto uses multiples of 24 (even 3DES uses 56 bytes keys)
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.tripleDes();
        SymmetricAlgorithmBuilder builder = new SymmetricAlgorithmBuilder(defaultFactories, engineFactory, keySize, 64);
        return builder.keyPassword(keyPassword);
    }

    /**
     * <p>
     * Creates a new builder for 3DES encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(String keyPassword) throws IllegalArgumentException {
        if (keyPassword == null) throw new IllegalArgumentException("You must provide non-null key password!");
        return tripleDes(Encoding.getBytes(keyPassword));
    }

    /**
     * <p>
     * Creates a new builder for 3DES encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p><p>
     * Note that during build process, you must call one of methods for specifying encryption key.
     * The methods are</p>
     * <ul>
     * <li>{@link SymmetricAlgorithmBuilder#keyPassword(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#key(byte[])}</li>
     * <li>{@link SymmetricAlgorithmBuilder#keyFactory(EncryptionKeyFactory)}</li>
     * </ul>
     *
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes() {
        return tripleDes(new byte[0]);
    }

    /**
     * <p>
     * Creates a new builder for RSA encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionFactories)} which defaults to {@link CryptoFactories}
     * that uses standard Java API implementations (you can read {@link CryptoFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * </p>
     *
     * @return builder for RSA encryption algorithm
     */
    public static RSAAlgorithmBuilder rsa() {
        AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> factory = defaultFactories.rsa();
        return new RSAAlgorithmBuilder(factory);
    }

}
