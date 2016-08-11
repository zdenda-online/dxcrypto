package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.encryption.crypto.RSACryptoEngineFactory;

/**
 * Factory for encryption engines factories that uses {@link EncryptionAlgorithms}.
 * You can use
 *
 * @see EncryptionAlgorithms
 */
public interface EncryptionEnginesFactories {

    /**
     * Creates a new engine factory for AES (128 bits).
     *
     * @return factory for AES
     */
    SymmetricEncryptionEngineFactory aes();

    /**
     * Creates a new engine factory for AES (256 bits).
     *
     * @return factory for AES-256
     */
    SymmetricEncryptionEngineFactory aes256();


    /**
     * Creates a new engine factory for Triple DES.
     *
     * @return factory for Triple DES
     */
    SymmetricEncryptionEngineFactory tripleDes();

    /**
     * Creates a new engine factory for RSA.
     *
     * @return factory for RSA
     */
    RSACryptoEngineFactory rsa();
}
