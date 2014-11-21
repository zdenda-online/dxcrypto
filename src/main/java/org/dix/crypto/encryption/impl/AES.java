package org.dix.crypto.encryption.impl;

import org.dix.crypto.encryption.CryptoEncryptionAlgorithm;
import org.dix.crypto.encryption.EncryptionException;

/**
 * AES encryption using cipher block chaining (CBC). For padding of input, PKCS5 is used.
 * For more information about the implementation, see {@link org.dix.crypto.encryption.CryptoEncryptionAlgorithm} from which this class extend.
 * <p/>
 * This class is immutable and can be considered thread safe.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see org.dix.crypto.encryption.CryptoEncryptionAlgorithm
 */
public class AES extends CryptoEncryptionAlgorithm {

    public AES(byte[] key) throws EncryptionException {
        this(key, DEFAULT_ENCODING);
    }

    public AES(byte[] key, String encoding) {
        super(key, 16 * 8, encoding);
    }

    @Override
    protected String getCipherName() {
        return "AES/CBC/PKCS5Padding";
    }
}
