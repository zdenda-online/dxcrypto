package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionException;

/**
 * AES encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Symmetric</li>
 * <li>Operation mode: Cipher Block Chaining (CBC)</li>
 * <li>Input padding: PKCS#5</li>
 * <li>Encryption key: PBKDF2 with HMAC-SHA1 as pseudo-random function</li>
 * </ul>
 * There is also a constructor that allows to use custom function for encryption key derivation if you don't want to
 * use default one (PBKDF2).
 * <p/>
 * For more information about the implementation, see {@link CryptoSymmetricAlgorithm} from which this class extend.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CryptoSymmetricAlgorithm
 */
public class AES extends CryptoSymmetricAlgorithm {

    /**
     * Creates a new instance of AES algorithm using given key.
     * Default {@link Encoding#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword password for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword) throws EncryptionException {
        super(keyFactory(keyPassword), Encoding.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of AES algorithm using given key password, and key salt.
     * Default {@link Encoding#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword password for encryption key derivation
     * @param keySalt     salt for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, byte[] keySalt) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt), Encoding.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of AES algorithm using given key password, key salt and iteration count.
     * Default {@link Encoding#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword     password for encryption key derivation
     * @param keySalt         salt for encryption key derivation
     * @param iterationsCount count of iterations for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, byte[] keySalt, int iterationsCount) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt, iterationsCount), Encoding.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of AES algorithm using given key and encoding used for strings.
     *
     * @param keyPassword password for encryption key derivation
     * @param encoding    encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword), encoding);
    }

    /**
     * Creates a new instance of AES algorithm using given key password, key salt and encoding used for strings.
     *
     * @param keyPassword password for encryption key derivation
     * @param keySalt     salt for encryption key derivation
     * @param encoding    encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, byte[] keySalt, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt), encoding);
    }

    /**
     * Creates a new instance of AES algorithm using given key password, key salt, iteration count and encoding
     * used for strings.
     *
     * @param keyPassword     password for encryption key derivation
     * @param keySalt         salt for encryption key derivation
     * @param iterationsCount count of iterations for encryption key derivation
     * @param encoding        encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, byte[] keySalt, int iterationsCount, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt, iterationsCount), encoding);
    }

    /**
     * Creates a new instance of AES algorithm with custom key factory and encoding.
     * You this construction if you don't want to use default PBKDF2 function for encryption key derivation.
     *
     * @param keyFactory factory for encryption key
     * @param encoding   encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public AES(CryptoKeyFactory keyFactory, String encoding) throws EncryptionException {
        super(keyFactory, encoding);
    }

    @Override
    protected String getCipherName() {
        return "AES/CBC/PKCS5Padding";
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword) {
        return new PBKDF2KeyFactory("AES", keyPassword, 16 * 8);
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword, byte[] keySalt) {
        return new PBKDF2KeyFactory("AES", keyPassword, 16 * 8, keySalt);
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword, byte[] keySalt, int iterCount) {
        return new PBKDF2KeyFactory("AES", keyPassword, 16 * 8, keySalt, iterCount);
    }
}
