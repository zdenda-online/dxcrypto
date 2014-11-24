package cz.d1x.dxcrypto.hash;

/**
 * Interface for builders that are able to construct {@link HashingAlgorithm}.
 * Note that it is strongly recommended that these builders will provide <strong>immutable</strong> algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface HashingAlgorithmBuilder {

    /**
     * Builds a new instance of hashing algorithm.
     *
     * @return algorithm instance
     * @throws HashingException possible exception when hashing algorithm cannot be built
     */
    HashingAlgorithm build() throws HashingException;
}
