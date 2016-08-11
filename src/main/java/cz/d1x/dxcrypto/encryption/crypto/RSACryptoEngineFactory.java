package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.RSAEngineFactory;

import java.math.BigInteger;
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
public class RSACryptoEngineFactory implements RSAEngineFactory {

    private final String algorithmName;

    public RSACryptoEngineFactory(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public EncryptionEngine newEngine(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent) {
        try {
            String shortAlgorithmName = algorithmName.contains("/") ? algorithmName.substring(0, algorithmName.indexOf("/")) : algorithmName;
            KeyFactory keyFactory = KeyFactory.getInstance(shortAlgorithmName);
            Key publicKey = null, privateKey = null;
            if (publicExponent != null) {
                RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
                publicKey = keyFactory.generatePublic(pubKeySpec);
            }
            if (privateExponent != null) {
                RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
                privateKey = keyFactory.generatePrivate(privKeySpec);
            }
            return new AsymmetricCryptoEngine(algorithmName, publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Unable to retrieve RSA public key", e);
        }
    }
}
