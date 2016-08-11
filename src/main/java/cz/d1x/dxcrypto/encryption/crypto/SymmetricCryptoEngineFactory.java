package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Factory that provides {@link EncryptionEngine} implementation for symmetric algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SymmetricCryptoEngineFactory implements SymmetricEncryptionEngineFactory {

    private final String algorithmName;
    private final String keyAlgorithmName;

    /**
     * Creates a new engine factory for given algorithm.
     *
     * @param algorithmName    full name of algorithm (with mode of operation and padding)
     * @param keyAlgorithmName full name of algorithm for key derivation
     */
    public SymmetricCryptoEngineFactory(String algorithmName, String keyAlgorithmName) {
        this.algorithmName = algorithmName;
        this.keyAlgorithmName = keyAlgorithmName;
    }

    @Override
    public EncryptionEngine newEngine(byte[] keyPassword, byte[] keySalt, int keyHashIterations, int keySize) {
        String shortAlgorithmName = algorithmName.contains("/") ? algorithmName.substring(0, algorithmName.indexOf("/")) : algorithmName;

        if ("AES".equals(shortAlgorithmName) && keySize >= 256) {
            checkJCE("AES", 256);
        }
        // if we support more algorithms that require JCE, we should check it the same way

        try {
            char[] keyEncoded = Encoding.getString(keyPassword).toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keySalt, keyHashIterations, keySize);
            SecretKey tmp = SecretKeyFactory.getInstance(keyAlgorithmName).generateSecret(keySpec);

            Key key = new SecretKeySpec(tmp.getEncoded(), shortAlgorithmName);
            return new SymmetricCryptoEngine(algorithmName, key);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
    }

    private void checkJCE(String name, int keySize) {
        if (!CryptoEnginesFactories.isJceInstalled()) {
            throw new IllegalArgumentException("Cipher " + name + " is not supported with key size of " + keySize + "b, " +
                    " probably Java Cryptography Extension (JCE) is not installed in your Java.");
        }
    }
}
