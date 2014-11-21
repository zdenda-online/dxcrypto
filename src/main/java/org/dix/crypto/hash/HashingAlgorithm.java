package org.dix.crypto.hash;

import org.dix.crypto.hash.impl.MD5;
import org.dix.crypto.hash.impl.SHA256;

/**
 * Interface for algorithms that are able to create hash of given input.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see MD5
 * @see SHA256
 */
public interface HashingAlgorithm {

    public static final String DEFAULT_ENCODING = "UTF-8";

    /**
     * Creates a hash from input text.
     *
     * @param text input text to be hashed
     * @return hashed text in hex string
     * @throws HashingException possible exception during hashing process
     */
    String hash(String text) throws HashingException;

    /**
     * Creates a hash from input bytes.
     *
     * @param bytes bytes to be hashed
     * @return hashed text in bytes
     * @throws HashingException possible exception during hashing process
     */
    byte[] hash(byte[] bytes) throws HashingException;

    /**
     * Gets encoding that is used for strings.
     *
     * @return used encoding
     */
    String getEncoding();
}
