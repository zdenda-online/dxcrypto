package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.hash.digest.MD5Builder;
import cz.d1x.dxcrypto.hash.digest.SHA256Builder;

/**
 * Interface for algorithms that are able to create hash from given input.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see MD5Builder
 * @see SHA256Builder
 */
public interface HashingAlgorithm {

    /**
     * Creates a hash from input text.
     *
     * @param input input text to be hashed
     * @return hashed text in hex string
     * @throws HashingException possible exception during hashing process
     */
    String hash(String input) throws HashingException;

    /**
     * Creates a hash from input bytes.
     *
     * @param input input to be hashed
     * @return hashed text in input
     * @throws HashingException possible exception during hashing process
     */
    byte[] hash(byte[] input) throws HashingException;
}
