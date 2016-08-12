package cz.d1x.dxcrypto.encryption;

/**
 * <p>
 * Interface for creation of encryption key.
 * </p><p>
 * These interfaces should be generic enough so they can be used by any encryption engine. That means that given
 * generic should NOT be implementation specific so they can be used in generic builders. This sometimes may lead into
 * simple passing of values (e.g. {@link RSAKey}.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricEncryptionEngineFactory
 * @see AsymmetricEncryptionEngineFactory
 */
public interface EncryptionKeyFactory<K> {

    /**
     * Creates a new key.
     *
     * @return bytes of encryption key
     * @throws EncryptionException exception if key cannot be created
     */
    K newKey() throws EncryptionException;
}
