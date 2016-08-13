package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class BouncyCastleSymmetricEngineFactory implements SymmetricEncryptionEngineFactory<ByteArray> {

    private final BlockCipher cipher;

    public BouncyCastleSymmetricEngineFactory(BlockCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public EncryptionEngine newEngine(ByteArray key) {
        KeyParameter keyParam = new KeyParameter(key.getValue());
        return new BouncyCastleSymmetricEngine(cipher, keyParam);
    }
}
