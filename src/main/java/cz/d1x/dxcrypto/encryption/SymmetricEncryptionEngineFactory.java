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
     * @param keyFactory factory for encryption key
     * @return encryption engine
     */
    EncryptionEngine newEngine(EncryptionKeyFactory<K> keyFactory);
}
