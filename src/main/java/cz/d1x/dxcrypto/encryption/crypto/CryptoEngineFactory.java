package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.EngineFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by d1x on 26.7.16.
 */
public class CryptoEngineFactory implements EngineFactory {

    private final String algorithmName;
    private final String shortAlgorithmName;

    public CryptoEngineFactory(String algorithmName, String shortAlgorithmName) {
        this.algorithmName = algorithmName;
        this.shortAlgorithmName = shortAlgorithmName;
    }

    @Override
    public EncryptionEngine newEngine(byte[] keyPassword, byte[] keySalt, int keyHashIterations, int keySize) {
        Key key;
        try {
            char[] keyEncoded = Encoding.getString(keyPassword).toCharArray();
            PBEKeySpec keySpec = new PBEKeySpec(keyEncoded, keySalt, keyHashIterations, keySize);
            SecretKey tmp = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec);
            key = new SecretKeySpec(tmp.getEncoded(), shortAlgorithmName);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new EncryptionException("Invalid key derivation algorithm", e);
        }
        return new CryptoEngine(algorithmName, key);
    }
}
