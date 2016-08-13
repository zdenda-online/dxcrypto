package cz.d1x.dxcrypto.encryption.key;

import java.math.BigInteger;

/**
 * Specification of RSA key.
 */
public class RSAKeyParams {

    private final BigInteger modulus;
    private final BigInteger exponent;

    public RSAKeyParams(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
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
}
