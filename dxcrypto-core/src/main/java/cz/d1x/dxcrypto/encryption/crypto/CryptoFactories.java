package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionFactories;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParams;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;

/**
 * <p>
 * Factories for engines that use Java standard API (javax.crypto) as encryption implementations.
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
 * Note that if you use AES-256 and stronger ciphers, JCE installation is required for this factory.
 * </p>
 */
public class CryptoFactories implements EncryptionFactories {

    @Override
    public EncryptionKeyFactory<ByteArray, DerivedKeyParams> derivedKeyFactory() {
        return new CryptoPBKDF2KeyFactory();
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes() {
        return new CryptoSymmetricEngineFactory("AES/CBC/PKCS5Padding");
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> aes256() {
        return new CryptoSymmetricEngineFactory("AES/CBC/PKCS5Padding");
    }

    @Override
    public SymmetricEncryptionEngineFactory<ByteArray> tripleDes() {
        return new CryptoSymmetricEngineFactory("DESede/CBC/PKCS5Padding");
    }

    @Override
    public AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> rsa() {
        return new CryptoRSAEngineFactory("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

}
