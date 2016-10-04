package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Factory that provides {@link EncryptionEngine} implementation for symmetric algorithms from Bouncy Castle.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class BouncyCastleSymmetricEngineFactory implements SymmetricEncryptionEngineFactory<ByteArray> {

    private final Class<? extends BlockCipher> blockCipherClass;

    public BouncyCastleSymmetricEngineFactory(Class<? extends BlockCipher> blockCipherClass) {
        this.blockCipherClass = blockCipherClass;
    }

    @Override
    public EncryptionEngine newEngine(ByteArray key) {
        KeyParameter keyParam = new KeyParameter(key.getValue());
        return new BouncyCastleSymmetricEngine(blockCipherClass, keyParam);
    }
}
