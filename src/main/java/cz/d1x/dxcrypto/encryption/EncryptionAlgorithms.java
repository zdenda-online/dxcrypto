package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.crypto.CryptoEnginesFactories;
import cz.d1x.dxcrypto.encryption.crypto.RSACryptoEngineFactory;

/**
 * Factory that provides builders for available encryption algorithms.
 * Create a new builder and when you are done with parameters, call build()
 * to retrieve {@link EncryptionAlgorithm} instance.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithms {

    private static EncryptionEnginesFactories defaultFactories = new CryptoEnginesFactories();

    /**
     * Sets a new global factories for encryption engines.
     * It defaults to {@link CryptoEnginesFactories}.
     *
     * @param factories factories to be set
     */
    public static void defaultFactories(EncryptionEnginesFactories factories) {
        if (factories == null) throw new IllegalArgumentException("You must provide non-null engine factories!");
        EncryptionAlgorithms.defaultFactories = factories;
    }

    /**
     * Creates a new builder for AES (128b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(byte[] keyPassword) throws IllegalArgumentException {
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.aes();
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, 128, 128);
    }

    /**
     * Creates a new builder for AES (128b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes(String keyPassword) throws IllegalArgumentException {
        return aes(Encoding.getBytes(keyPassword));
    }

    /**
     * Creates a new builder for AES (256b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     * <p>
     * Note that if you use default {@link CryptoEnginesFactories}, you may need JCE installed for AES-256.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(byte[] keyPassword) throws IllegalArgumentException {
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.aes256();
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, 256, 128);
    }

    /**
     * Creates a new builder for AES (256b) encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms) .
     * <p>
     * Note that if you use default {@link CryptoEnginesFactories}, you may need JCE installed for AES-256.
     * </p>
     *
     * @param keyPassword password for key derivation
     * @return builder for AES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder aes256(String keyPassword) throws IllegalArgumentException {
        return aes256(Encoding.getBytes(keyPassword));
    }

    /**
     * Creates a new builder for 3DES encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(byte[] keyPassword) throws IllegalArgumentException {
        int keySize = (3 * 8) * 8; // crypto uses multiples of 24 (even 3DES uses 56 bytes keys)
        SymmetricEncryptionEngineFactory engineFactory = defaultFactories.tripleDes();
        return new SymmetricAlgorithmBuilder(engineFactory, keyPassword, keySize, 64);
    }

    /**
     * Creates a new builder for 3DES encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     *
     * @param keyPassword password for key derivation
     * @return builder for 3DES encryption algorithm
     * @throws IllegalArgumentException exception if passed key password is null
     */
    public static SymmetricAlgorithmBuilder tripleDes(String keyPassword) throws IllegalArgumentException {
        return tripleDes(Encoding.getBytes(keyPassword));
    }

    /**
     * Creates a new builder for RSA encryption. Engine for encryption is dependent on
     * {@link #defaultFactories(EncryptionEnginesFactories)} which defaults to {@link CryptoEnginesFactories}
     * that uses standard Java API implementations (you can read {@link CryptoEnginesFactories} javadoc that
     * describes what parameters it uses for encryption algorithms).
     *
     * @return builder for RSA encryption algorithm
     */
    public static RSAAlgorithmBuilder rsa() {
        RSACryptoEngineFactory factory = defaultFactories.rsa();
        return new RSAAlgorithmBuilder(factory);
    }

}
