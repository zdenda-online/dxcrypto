package cz.d1x.crypto.encryption;

/**
 * Factory that is able to provide encryption key (e.g. via some derivation function).
 * It can be symmetric key or part (public/private) of asymmetric key.
 * Given generic is class of key that is provided by this factory.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface KeyFactory<K> {

    /**
     * Gets a key for encryption or decryption.
     *
     * @return key for encryption
     * @throws EncryptionException possible exception if key cannot be constructed
     */
    K getKey() throws EncryptionException;
}
