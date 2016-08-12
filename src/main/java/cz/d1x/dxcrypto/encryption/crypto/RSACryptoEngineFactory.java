package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.*;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Factory that provides {@link EncryptionEngine} implementation for RSA algorithm.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RSACryptoEngineFactory implements AsymmetricEncryptionEngineFactory<RSAKey, RSAKey> {

    private final String algorithmName;

    public RSACryptoEngineFactory(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public EncryptionEngine newEngine(EncryptionKeyFactory<RSAKey> publicKeyFactory, EncryptionKeyFactory<RSAKey> privateKeyFactory) {
        try {
            String shortAlgorithmName = algorithmName.contains("/") ? algorithmName.substring(0, algorithmName.indexOf("/")) : algorithmName;
            KeyFactory keyFactory = KeyFactory.getInstance(shortAlgorithmName);
            Key publicKey = null, privateKey = null;
            if (publicKeyFactory != null) {
                RSAKey key = publicKeyFactory.newKey();
                RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(key.getModulus(), key.getExponent());
                publicKey = keyFactory.generatePublic(pubKeySpec);
            }
            if (privateKeyFactory != null) {
                RSAKey key = privateKeyFactory.newKey();
                RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(key.getModulus(), key.getExponent());
                privateKey = keyFactory.generatePrivate(privKeySpec);
            }
            return new AsymmetricCryptoEngine(algorithmName, publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Unable to retrieve RSA public key", e);
        }
    }
}
