package cz.d1x.dxcrypto.encryption;

/**
 * Interface for builders that are able to construct {@link EncryptionAlgorithm}.
 * Note that it is strongly recommended that these builders will provide <strong>immutable</strong> algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface EncryptionAlgorithmBuilder {

    /**
     * Builds a new instance of encryption algorithm.
     *
     * @return algorithm instance
     * @throws EncryptionException possible exception when encryption algorithm cannot be built
     */
    EncryptionAlgorithm build() throws EncryptionException;
}
