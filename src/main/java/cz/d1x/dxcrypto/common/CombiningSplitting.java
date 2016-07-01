package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Algorithm that is able to combine two inputs into one and vice versa split one input back to two originals.
 * These functions are reversible, so splitting combined text must result in original text again.
 * In formula:
 * </p>
 * <pre>split(combine([input1, input2])) == [input1, input2]</pre>
 * <p>
 * Typical usage is for combining initialization vector and cipher text during encryption and splitting back
 * during decryption.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see Combining
 * @see Splitting
 * @see ConcatAlgorithm
 */
public interface CombiningSplitting extends Combining, Splitting {
}
