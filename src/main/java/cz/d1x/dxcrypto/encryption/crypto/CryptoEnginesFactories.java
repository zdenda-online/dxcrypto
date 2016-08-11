package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionEnginesFactories;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 * <p>
 * Factories for engines that use Java standard API (javax.crypto) as encryption implementations.
 * This factory creates these algorithms:
 * </p>
 * <ul>
 * <li>AES-128: CBC mode with PKCS#5 padding and PBKDF2 with HMAC-SHA1 for key derivation</li>
 * <li>AES-256: CBC mode with PKCS#5 padding and PBKDF2 with HMAC-SHA1 for key derivation</li>
 * <li>3DES: CBC mode with PKCS#5 padding and PBKDF2 with HMAC-SHA1 for key derivation</li>
 * <li>RSA: ECB mode with OAEP SHA-256 and MGF1 padding</li>
 * </ul>
 * <p>
 * Note that if you use AES-256 and stronger ciphers, JCE installation is required for this factory.
 * You can check whether it is installed by {@link CryptoEnginesFactories#isJceInstalled()}.
 * </p>
 */
public class CryptoEnginesFactories implements EncryptionEnginesFactories {

    @Override
    public SymmetricEncryptionEngineFactory aes() {
        return new SymmetricCryptoEngineFactory("AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
    }

    @Override
    public SymmetricEncryptionEngineFactory aes256() {
        return new SymmetricCryptoEngineFactory("AES/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
    }

    @Override
    public SymmetricEncryptionEngineFactory tripleDes() {
        return new SymmetricCryptoEngineFactory("DESede/CBC/PKCS5Padding", "PBKDF2WithHmacSHA1");
    }

    @Override
    public RSACryptoEngineFactory rsa() {
        return new RSACryptoEngineFactory("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    /**
     * Checks whether Java Cryptography Extension (JCE) is installed. Thus stronger ciphers (e.g. AES-256 can be used).
     *
     * @return true if JCE is installed, otherwise false
     */
    public static boolean isJceInstalled() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES") == Integer.MAX_VALUE;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
