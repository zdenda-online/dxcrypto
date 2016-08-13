package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.key.RSAKeyParams;

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
public class CryptoRSAEngineFactory implements AsymmetricEncryptionEngineFactory<RSAKeyParams, RSAKeyParams> {

    private final String algorithmName;

    public CryptoRSAEngineFactory(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public EncryptionEngine newEngine(RSAKeyParams publicKey, RSAKeyParams privateKey) {
        try {
            String shortAlgorithmName = algorithmName.contains("/") ? algorithmName.substring(0, algorithmName.indexOf("/")) : algorithmName;
            KeyFactory keyFactory = KeyFactory.getInstance(shortAlgorithmName);
            Key pubKey = null, privKey = null;
            if (publicKey != null) {
                RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent());
                pubKey = keyFactory.generatePublic(pubKeySpec);
            }
            if (privateKey != null) {
                RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getExponent());
                privKey = keyFactory.generatePrivate(privKeySpec);
            }
            return new CryptoAsymmetricEngine(algorithmName, pubKey, privKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Unable to retrieve RSA public key", e);
        }
    }
}
