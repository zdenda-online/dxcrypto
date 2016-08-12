package cz.d1x.dxcrypto.encryption;

/**
 * Interface for factories that are able to provide encryption engines for RSA.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface AsymmetricEncryptionEngineFactory<PUBKEY, PRIVKEY> {

    /**
     * Creates a new encryption engine.
     * Note that you can pass only one of key, created algorithm then will be only able to encrypt/decrypt
     * messages depending on what key you provided.
     *
     * @param publicKey  public key for encryption
     * @param privateKey private key for decryption
     * @return encryption engine
     */
    EncryptionEngine newEngine(PUBKEY publicKey, PRIVKEY privateKey);
}
