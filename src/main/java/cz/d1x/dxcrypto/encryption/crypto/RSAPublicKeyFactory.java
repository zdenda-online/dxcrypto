package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Key factory for RSA public key.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RSAPublicKeyFactory extends CryptoKeyFactory {

    private final BigInteger modulus;
    private final BigInteger exponent;

    /**
     * Creates a new RSA public key factory with given modulus and exponent.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of public key
     */
    public RSAPublicKeyFactory(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    @Override
    public Key getKey() throws EncryptionException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
            return keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Unable to retrieve RSA public key", e);
        }
    }
}
