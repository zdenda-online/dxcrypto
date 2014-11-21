package org.dix.crypto.encryption.impl;

import org.dix.crypto.encryption.CryptoEncryptionAlgorithm;
import org.dix.crypto.encryption.EncryptionException;

/**
 * AES encryption using cipher block chaining (CBC). For padding of input, PKCS5 is used.
 * For more information about the implementation, see {@link CryptoEncryptionAlgorithm} from which this class extend.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CryptoEncryptionAlgorithm
 */
public class AES extends CryptoEncryptionAlgorithm {

    /**
     * Creates a new instance of AES algorithm using given key.
     *
     * @param keyPassword password for encryption key derivation
     * @throws EncryptionException possible exception whether algorithm cannot be initialized
     */
    public AES(byte[] keyPassword) throws EncryptionException {
        this(keyPassword, DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of AES algorithm using given key and encoding used for strings.
     *
     * @param keyPassword password for encryption key derivation
     * @param encoding    encoding for input and output strings
     * @throws EncryptionException possible exception whether algorithm cannot be initialized
     */
    public AES(byte[] keyPassword, String encoding) throws EncryptionException {
        super(keyPassword, 16 * 8, encoding);
    }

    @Override
    protected String getCipherName() {
        return "AES/CBC/PKCS5Padding";
    }
}
