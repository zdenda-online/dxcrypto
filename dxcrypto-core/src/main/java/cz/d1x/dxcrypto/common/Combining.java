package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Algorithm that is able to combine two inputs into one.
 * </p><p>
 * Typical usage is for combining an input text and salt before it is processed by hashing algorithm.
 * Also it is used for combining initialization vector and cipher text during encryption.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see ConcatAlgorithm
 */
public interface Combining {

    /**
     * Combines together two byte arrays.
     *
     * @param input1 first input to be combined
     * @param input2 second input to be combined
     * @return combined inputs into one
     */
    byte[] combine(byte[] input1, byte[] input2);
}
