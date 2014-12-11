package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Algorithm that is able to combine two inputs into one and vice versa split one input back to two.
 * These functions are reversible, so splitting combined text must result in original text again.
 * In formula: {@code split(combine([input1, input])) == [input1, input2]}.
 * </p><p>
 * These algorithms are used for combining an input text and salt before it is processed by hashing algorithm.
 * Also it is used for combining initialization vector and cipher text during encryption so IV is part of final output or
 * splitting back during decryption.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see ConcatCombineAlgorithm
 */
public interface CombineAlgorithm {

    /**
     * Combines together two byte arrays.
     *
     * @param input1 first input to be combined
     * @param input2 second input to be combined
     * @return combined inputs into one
     */
    byte[] combine(byte[] input1, byte[] input2);

    /**
     * Splits input (that was combined earlier) back to original.
     *
     * @param combined previously combined input
     * @return two dimensional array of two original inputs (byte[2][])
     */
    byte[][] split(byte[] combined);
}
