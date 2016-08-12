package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParameters;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParameters;

/**
 * Abstract factory for encryption engines and key factories that uses {@link EncryptionAlgorithms}.
 * If you want custom implementation, this is the interface you should implement and later set it globally by
 * {@link EncryptionAlgorithms#defaultFactories(EncryptionFactories)}.
 *
 * @see EncryptionAlgorithms
 */
public interface EncryptionFactories {

    /**
     * Creates a new key factory for derived keys (typically by hash function).
     * Used for derivation of key by {@link SymmetricEncryptionEngineFactory} (AES, 3DES).
     * It is recommended to use PBKDF2 (HMAC with SHA-1) as it is used for default crypto implementation.
     *
     * @return key factory for key derivation
     */
    EncryptionKeyFactory<ByteArray, DerivedKeyParameters> derivedKeyFactory();

    /**
     * Creates a new engine factory for AES (128 bits).
     *
     * @return factory for AES
     */
    SymmetricEncryptionEngineFactory<ByteArray> aes();

    /**
     * Creates a new engine factory for AES (256 bits).
     *
     * @return factory for AES-256
     */
    SymmetricEncryptionEngineFactory<ByteArray> aes256();


    /**
     * Creates a new engine factory for Triple DES.
     *
     * @return factory for Triple DES
     */
    SymmetricEncryptionEngineFactory<ByteArray> tripleDes();

    /**
     * Creates a new engine factory for RSA.
     *
     * @return factory for RSA
     */
    AsymmetricEncryptionEngineFactory<RSAKeyParameters, RSAKeyParameters> rsa();
}
