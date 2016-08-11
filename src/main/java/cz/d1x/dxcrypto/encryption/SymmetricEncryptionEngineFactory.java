package cz.d1x.dxcrypto.encryption;

/**
 * Interface for factories that are able to provide encryption engines.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface SymmetricEncryptionEngineFactory {

    /**
     * Creates a new encryption engine.
     *
     * @param keyPassword       password for generation of encryption key
     * @param keySalt           salt for generation of encryption key
     * @param keyHashIterations count of hash function iterations for generation of encryption key
     * @param keySize           size of the key
     * @return encryption engine
     */
    EncryptionEngine newEngine(byte[] keyPassword, byte[] keySalt, int keyHashIterations, int keySize);
}
