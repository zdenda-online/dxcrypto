package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.impl.MD5;
import cz.d1x.crypto.hash.impl.SHA256;

/**
 * Interface for algorithms that are able to create hash of given input.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see MD5
 * @see SHA256
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
     * Creates a hash from input input.
     *
     * @param input input to be hashed
     * @return hashed text in input
     * @throws HashingException possible exception during hashing process
     */
    byte[] hash(byte[] input) throws HashingException;
}
