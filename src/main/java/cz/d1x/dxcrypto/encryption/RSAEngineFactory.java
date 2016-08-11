package cz.d1x.dxcrypto.encryption;

import java.math.BigInteger;

/**
 * Interface for factories that are able to provide encryption engines for RSA.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface RSAEngineFactory {

    /**
     * Creates a new encryption engine.
     * Note that you can pass only one of exponent, created algorithm then will be only able to encrypt/decrypt
     * messages depending on what exponent you provided.
     *
     * @param modulus         modulus of RSA keys
     * @param publicExponent  exponent of public RSA key
     * @param privateExponent exponent of private RSA key
     * @return encryption engine
     */
    EncryptionEngine newEngine(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent);
}
