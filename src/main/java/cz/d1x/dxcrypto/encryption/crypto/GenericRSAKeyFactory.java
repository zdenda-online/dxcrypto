package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.EncryptionKeyFactory;
import cz.d1x.dxcrypto.encryption.RSAKey;

import java.math.BigInteger;

/**
 * Key factory that uses implementation from javax.crypto for RSA key derivation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class GenericRSAKeyFactory implements EncryptionKeyFactory<RSAKey> {

    private final BigInteger modulus;
    private final BigInteger exponent;
    private final boolean isPublicKey;

    public GenericRSAKeyFactory(BigInteger modulus, BigInteger exponent, boolean isPublicKey) {
        this.modulus = modulus;
        this.exponent = exponent;
        this.isPublicKey = isPublicKey;
    }

    @Override
    public RSAKey newKey() throws EncryptionException {
        return new RSAKey(modulus, exponent, isPublicKey);
    }
}
