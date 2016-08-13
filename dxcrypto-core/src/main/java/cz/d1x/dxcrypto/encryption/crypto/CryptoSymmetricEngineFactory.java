package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;

/**
 * Factory that provides {@link EncryptionEngine} implementation for symmetric algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class CryptoSymmetricEngineFactory implements SymmetricEncryptionEngineFactory<ByteArray> {

    private final String algorithmName;

    /**
     * Creates a new engine factory for given algorithm.
     *
     * @param algorithmName full name of algorithm (with mode of operation and padding)
     */
    public CryptoSymmetricEngineFactory(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public EncryptionEngine newEngine(ByteArray key) {
        return new CryptoSymmetricEngine(algorithmName, key.getValue());
    }
}
