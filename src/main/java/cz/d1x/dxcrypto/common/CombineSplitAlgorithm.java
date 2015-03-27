package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Algorithm that is able to combine two inputs into one and vice versa split one input back to two.
 * These functions are reversible, so splitting combined text must result in original text again.
 * In formula:
 * <pre>split(combine([input1, input2])) == [input1, input2]</pre>
 * </p><p>
 * Typical usage is for combining initialization vector and cipher text during encryption and splitting back
 * during decryption.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CombineAlgorithm
 * @see SplitAlgorithm
 * @see ConcatAlgorithm
 */
public interface CombineSplitAlgorithm extends CombineAlgorithm, SplitAlgorithm {
}
