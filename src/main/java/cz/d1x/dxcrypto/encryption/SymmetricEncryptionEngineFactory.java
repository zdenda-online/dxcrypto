package cz.d1x.dxcrypto.encryption;

/**
 * Interface for factories that are able to provide encryption engines.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface SymmetricEncryptionEngineFactory<K> {

    /**
     * Creates a new encryption engine.
     *
     * @param key key for encryption engine
     * @return encryption engine
     */
    EncryptionEngine newEngine(K key);
}
