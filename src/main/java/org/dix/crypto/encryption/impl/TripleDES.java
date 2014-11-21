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
public class TripleDES extends CryptoEncryptionAlgorithm {

    /**
     * Creates a new instance of Triple DES algorithm using given key.
     *
     * @param key key for encryption
     * @throws EncryptionException possible exception whether algorithm cannot be initialized
     */
    public TripleDES(byte[] key) throws EncryptionException {
        this(key, DEFAULT_ENCODING);
    }

    /**
     * Creates a new instance of Triple DES algorithm using given key and encoding used for strings.
     *
     * @param key      key for encryption
     * @param encoding encoding for input and output strings
     * @throws EncryptionException possible exception whether algorithm cannot be initialized
     */
    public TripleDES(byte[] key, String encoding) throws EncryptionException {
        super(key, 24 * 8, encoding);
    }

    @Override
    protected String getCipherName() {
        return "DESede/CBC/PKCS5Padding";
    }
}
