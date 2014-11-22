package cz.d1x.crypto.encryption.crypto;

import cz.d1x.crypto.TextUtil;
import cz.d1x.crypto.encryption.EncryptionException;

/**
 * Triple DES (or 3DES) encryption algorithm with these properties:
 * <ul>
 * <li>Type of cipher: Symmetric</li>
 * <li>Operation mode: Cipher Block Chaining (CBC)</li>
 * <li>Input padding: PKCS#5</li>
 * <li>Encryption key: PBKDF2 with HMAC-SHA1 as pseudo-random function</li>
 * </ul>
 * There is also a constructor that allows to use custom function for encryption key derivation if you don't want to
 * use default one (PBKDF2).
 * <p/>
 * For more information about the implementation, see {@link CryptoSymmetricKeyAlgorithm} from which this class extend.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CryptoSymmetricKeyAlgorithm
 */
public class TripleDES extends CryptoSymmetricKeyAlgorithm {

    /**
     * Creates a new instance of 3DES algorithm using given key.
     * Default {@link TextUtil#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword password for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword) throws EncryptionException {
        super(keyFactory(keyPassword), TextUtil.DEFAULT_ENCODING);
    }


    /**
     * Creates a new instance of 3DES algorithm using given key password, and key salt.
     * Default {@link TextUtil#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword password for encryption key derivation
     * @param keySalt     salt for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword, byte[] keySalt) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt), TextUtil.DEFAULT_ENCODING);
    }


    /**
     * Creates a new instance of 3DES algorithm using given key password, key salt and iteration count.
     * Default {@link TextUtil#DEFAULT_ENCODING} is used as encoding.
     *
     * @param keyPassword     password for encryption key derivation
     * @param keySalt         salt for encryption key derivation
     * @param iterationsCount count of iterations for encryption key derivation
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword, byte[] keySalt, int iterationsCount) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt, iterationsCount), TextUtil.DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of 3DES algorithm using given key and encoding used for strings.
     *
     * @param keyPassword password for encryption key derivation
     * @param encoding    encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword), encoding);
    }

    /**
     * Creates a new instance of 3DES algorithm using given key password, key salt and encoding used for strings.
     *
     * @param keyPassword password for encryption key derivation
     * @param keySalt     salt for encryption key derivation
     * @param encoding    encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword, byte[] keySalt, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt), encoding);
    }

    /**
     * Creates a new instance of 3DES algorithm using given key password, key salt, iteration count and encoding
     * used for strings.
     *
     * @param keyPassword     password for encryption key derivation
     * @param keySalt         salt for encryption key derivation
     * @param iterationsCount count of iterations for encryption key derivation
     * @param encoding        encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(byte[] keyPassword, byte[] keySalt, int iterationsCount, String encoding) throws EncryptionException {
        super(keyFactory(keyPassword, keySalt, iterationsCount), encoding);
    }

    /**
     * Creates a new instance of 3DES algorithm with custom key factory and encoding.
     * You this construction if you don't want to use default PBKDF2 function for encryption key derivation.
     *
     * @param keyFactory factory for encryption key
     * @param encoding   encoding for input and output strings
     * @throws EncryptionException possible exception if algorithm cannot be initialized
     */
    public TripleDES(CryptoKeyFactory keyFactory, String encoding) throws EncryptionException {
        super(keyFactory, encoding);
    }

    @Override
    protected String getCipherName() {
        return "DESede/CBC/PKCS5Padding";
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword) {
        return new PBKDF2KeyFactory("DESede", keyPassword, 24 * 8);
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword, byte[] keySalt) {
        return new PBKDF2KeyFactory("DESede", keyPassword, 24 * 8, keySalt);
    }

    private static CryptoKeyFactory keyFactory(byte[] keyPassword, byte[] keySalt, int iterCount) {
        return new PBKDF2KeyFactory("DESede", keyPassword, 24 * 8, keySalt, iterCount);
    }
}
