package cz.d1x.dxcrypto.encryption.key;

import java.math.BigInteger;

/**
 * Specification of RSA key.
 */
public class RSAKeyParameters {

    private final BigInteger modulus;
    private final BigInteger exponent;
    private final boolean isPublicKey;

    public RSAKeyParameters(BigInteger modulus, BigInteger exponent, boolean isPublicKey) {
        this.modulus = modulus;
        this.exponent = exponent;
        this.isPublicKey = isPublicKey;
    }

    /**
     * Gets modulus of RSA key.
     *
     * @return modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Gets exponent of RSA key.
     *
     * @return exponent
     */
    public BigInteger getExponent() {
        return exponent;
    }

    /**
     * Gets a flag whether key is public or private.
     *
     * @return true if key is supposed to be public, false if private
     */
    public boolean isPublicKey() {
        return isPublicKey;
    }
}
