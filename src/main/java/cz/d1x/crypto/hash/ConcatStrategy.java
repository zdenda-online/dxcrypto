package cz.d1x.crypto.hash;

/**
 * Strategy for {@link SaltingAdapter} which drives how input text and salt will be concatenated together.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public interface ConcatStrategy {

    /**
     * Concatenates together input text and salt.
     *
     * @param input input (plain text) to be hashed
     * @param salt  salt to be added to input before hashing
     * @return concatenated input for hashing function
     */
    byte[] concatenate(byte[] input, byte[] salt);
}
