package cz.d1x.dxcrypto.hash;

/**
 * Interface for algorithms that are able to create hash from given input and given salt.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see HashingAlgorithm
 */
public interface SaltedHashingAlgorithm {

    /**
     * Creates a hash from given input and given salt.
     *
     * @param input input to be hashed
     * @param salt  salt to be added to input
     * @return salted and hashed input
     * @throws HashingException possible exception during hashing
     */
    String hash(String input, String salt) throws HashingException;

    /**
     * Creates a hash from given input bytes and given salt bytes.
     *
     * @param input input to be hashed
     * @param salt  salt to be added to input
     * @return salted and hashed input
     * @throws HashingException possible exception during hashing process
     */
    byte[] hash(byte[] input, byte[] salt) throws HashingException;
}
