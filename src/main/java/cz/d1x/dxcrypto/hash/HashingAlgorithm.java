package cz.d1x.dxcrypto.hash;

/**
 * Interface for algorithms that are able to create hash from given input.
 * To create them, it is recommended to use {@link HashingAlgorithms} factory class.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see HashingAlgorithms
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
