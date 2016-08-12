package cz.d1x.dxcrypto.encryption.key;

import cz.d1x.dxcrypto.encryption.AsymmetricEncryptionEngineFactory;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.SymmetricEncryptionEngineFactory;

/**
 * <p>
 * Interface for creation of encryption key.
 * </p><p>
 * These interfaces should be generic enough so they can be used by any encryption engine. That means that given
 * generic should NOT be implementation specific so they can be used in generic builders. This sometimes may lead into
 * simple passing of values (e.g. {@link RSAKeyParameters}.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SymmetricEncryptionEngineFactory
 * @see AsymmetricEncryptionEngineFactory
 */
public interface EncryptionKeyFactory<K, KP> {

    /**
     * Creates a new key.
     *
     * @param keyParams parameters for creation of key
     * @return bytes of encryption key
     * @throws EncryptionException exception if key cannot be created
     */
    K newKey(KP keyParams) throws EncryptionException;
}
