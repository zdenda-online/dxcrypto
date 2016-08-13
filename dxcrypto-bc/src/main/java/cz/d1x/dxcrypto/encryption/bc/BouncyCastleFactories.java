package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionFactories;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParams;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;

public class BouncyCastleFactories implements EncryptionFactories {

    @Override
    public EncryptionKeyFactory<ByteArray, DerivedKeyParams> derivedKeyFactory() {
        return new BouncyCastlePBKDF2KeyFactory();
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes256() {
        return new BouncyCastleSymmetricEngineFactory(new AESEngine());
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes() {
        return new BouncyCastleSymmetricEngineFactory(new AESEngine());
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> tripleDes() {
        return new BouncyCastleSymmetricEngineFactory(new DESedeEngine());
    }

    @Override
    public AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> rsa() {
        return new BouncyCastleRSAEngineFactory();
    }
}
