package cz.d1x.dxcrypto.encryption;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

/**
 * Key factory for RSA private key.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RSAPrivateKeyFactory implements cz.d1x.dxcrypto.encryption.KeyFactory<Key> {

    private final BigInteger modulus;
    private final BigInteger exponent;

    /**
     * Creates a new RSA private key factory with given modulus and exponent.
     *
     * @param modulus  modulus of key
     * @param exponent exponent of private key
     */
    public RSAPrivateKeyFactory(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    @Override
    public Key getKey() throws EncryptionException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, exponent);
            return keyFactory.generatePrivate(privKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Unable to retrieve RSA private key", e);
        }
    }
}
