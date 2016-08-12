package cz.d1x.dxcrypto.encryption;

/**
 * Interface for factories that are able to provide encryption engines for RSA.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface AsymmetricEncryptionEngineFactory<PUBKEY, PRIVKEY> {

    /**
     * Creates a new encryption engine.
     * Note that you can pass only one of exponent, created algorithm then will be only able to encrypt/decrypt
     * messages depending on what exponent you provided.
     *
     * @param publicKeyFactory  key factory for public keys
     * @param privateKeyFactory key factory for private keys
     * @return encryption engine
     */
    EncryptionEngine newEngine(EncryptionKeyFactory<PUBKEY> publicKeyFactory, EncryptionKeyFactory<PRIVKEY> privateKeyFactory);
}
