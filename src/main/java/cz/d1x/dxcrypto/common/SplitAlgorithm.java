package cz.d1x.dxcrypto.common;

/**
 * <p>
 * Algorithm that is able to split one input into two originals. These algorithms should know by what method was the
 * input combined for the first time. This is why they are usually used together with {@link CombineAlgorithm} via
 * {@link CombineSplitAlgorithm}.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see CombineSplitAlgorithm
 * @see ConcatAlgorithm
 */
public interface SplitAlgorithm {

    /**
     * Splits input (that was combined earlier) back to original.
     *
     * @param combined previously combined input
     * @return two dimensional array of two original inputs (byte[2][])
     */
    byte[][] split(byte[] combined);
}
