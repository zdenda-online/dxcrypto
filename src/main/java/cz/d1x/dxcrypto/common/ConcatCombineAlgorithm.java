package cz.d1x.dxcrypto.common;

import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.crypto.SymmetricAlgorithm;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

/**
 * Simplest implementation of combine algorithm. It combines inputs by concatenation of two values together:<br/>
 * [first input + second input]. It implies that this algorithm needs to know length of first input if split operation
 * will be used.
 * <p/>
 * Note that this class is immutable so when this first input length is once set, then all first inputs needs to have
 * this length if split operation will be used. Otherwise unpredictable outputs or {@link IllegalArgumentException}
 * may occur during split (combine operation will work always).
 * <p/>
 * This requirement is not a problem for (input + salt) usage before hashing because it is not expected to split these
 * values later on. Also it is not a problem for (IV + cipher text) during CBC because first input (IV) has always
 * fixed length equal to cipher block size.
 * <p/>
 * On the other hand, if you need split operation and expect dynamic size of both inputs, you must create new instance
 * every time you want to combine and split.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SaltingAdapter
 * @see SymmetricAlgorithm
 */
public class ConcatCombineAlgorithm implements CombineAlgorithm {

    private final int input1Length;

    /**
     * Creates a new instance of combine algorithm.
     * Use this constructor if you expect only to combine inputs but not splitting back.
     */
    public ConcatCombineAlgorithm() {
        this.input1Length = -1;
    }

    /**
     * Creates a new instance of combine algorithm.
     * Use this constructor if you expect both combine and splitting back of inputs.
     *
     * @param input1Length expected length of first inputs
     */
    public ConcatCombineAlgorithm(int input1Length) {
        if (input1Length < 0) {
            throw new IllegalArgumentException("Input length must be greater than 0");
        }
        this.input1Length = input1Length;
    }

    @Override
    public byte[] combine(byte[] input1, byte[] input2) {
        byte[] out = new byte[input1.length + input2.length];
        System.arraycopy(input1, 0, out, 0, input1.length);
        System.arraycopy(input2, 0, out, input1.length, input2.length);
        return out;
    }

    @Override
    public byte[][] split(byte[] combined) {
        if (input1Length == -1) {
            throw new EncryptionException("Input length was not specified (wrong constructor), unable to split input");
        }
        if (combined.length <= input1Length) {
            throw new EncryptionException("Given input is too short, probably it was not combined by this instance");
        }
        byte[] input1 = new byte[input1Length];
        byte[] input2 = new byte[combined.length - input1.length];
        System.arraycopy(combined, 0, input1, 0, input1.length);
        System.arraycopy(combined, input1.length, input2, 0, input2.length);

        byte[][] out = new byte[2][];
        out[0] = input1;
        out[1] = input2;
        return out;
    }
}
