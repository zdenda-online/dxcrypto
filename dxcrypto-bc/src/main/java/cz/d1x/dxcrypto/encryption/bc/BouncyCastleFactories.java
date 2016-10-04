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

/**
 * <p>
 * Factories for engines that use Bouncy Castle API as encryption implementations.
 * This factory creates these algorithms:
 * </p>
 * <ul>
 * <li>AES-128: CBC mode with PKCS#5 padding</li>
 * <li>AES-256: CBC mode with PKCS#5 padding</li>
 * <li>3DES: CBC mode with PKCS#5 padding</li>
 * <li>RSA: ECB mode with OAEP SHA-256 and MGF1 padding</li>
 * <li>Derived keys: PBKDF2 with HMAC-SHA1</li>
 * </ul>
 * <p>
 * Compared to {@link cz.d1x.dxcrypto.encryption.crypto.CryptoFactories}, this one does not require JCE installed for
 * stronger ciphers, e.g. AES-256.
 * </p>
 */
public class BouncyCastleFactories implements EncryptionFactories {

    @Override
    public EncryptionKeyFactory<ByteArray, DerivedKeyParams> derivedKeyFactory() {
        return new BouncyCastlePBKDF2KeyFactory();
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes256() {
        return new BouncyCastleSymmetricEngineFactory(AESEngine.class);
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes() {
        return new BouncyCastleSymmetricEngineFactory(AESEngine.class);
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> tripleDes() {
        return new BouncyCastleSymmetricEngineFactory(DESedeEngine.class);
    }

    @Override
    public AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> rsa() {
        return new BouncyCastleRSAEngineFactory();
    }
}
