package cz.d1x.dxcrypto.common;

import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.crypto.SymmetricAlgorithm;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

/**
 * <p>
 * Simplest implementation of combine/split algorithm. It combines inputs consecutively (simple concatenation).
 * It implies that this algorithm needs to know length of first input if {@link #split(byte[])} will be used.
 * </p>
 * <ul>
 * <li>If you expect to use only {@link #combine(byte[], byte[])}, there is no need to provide the length of first input, so
 * you can use {@link #ConcatAlgorithm()} constructor.</li>
 * <li>If you expect to use both {@link #combine(byte[], byte[])} and {@link #split(byte[])}, you must provide expected
 * length of first input, so you should use {@link #ConcatAlgorithm(int)} constructor.</li>
 * </ul>
 * <p>
 * Note that this class is immutable so when this first input length is once set, then all first inputs needs to have
 * this length, otherwise {@link IllegalArgumentException} may occur.
 * </p><p>
 * This algorithm is sufficient for most cases. It is not a problem for (input + salt) usage before hashing because only
 * combine operation is used (split is not needed). Also it is not a problem for (IV + cipher text) during CBC because
 * first input (IV) has always fixed length equal to cipher block size.
 * </p><p>
 * On the other hand, if you need {@link #split(byte[])} and expect dynamic size of both inputs, you must create new instance
 * every time you want to combine and split.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SaltingAdapter
 * @see SymmetricAlgorithm
 */
public class ConcatAlgorithm implements CombineSplitAlgorithm {

    private static final int INPUT_LENGTH_NOT_SET = -1;
    private final int input1Length;

    /**
     * Creates a new instance of combine algorithm.
     * Use this constructor if you expect use only to {@link #combine(byte[], byte[])} inputs but <strong>not</strong>
     * {@link #split(byte[])}.
     */
    public ConcatAlgorithm() {
        this.input1Length = INPUT_LENGTH_NOT_SET;
    }

    /**
     * Creates a new instance of combine algorithm.
     * Use this constructor if you expect to use both {@link #combine(byte[], byte[])} and {@link #split(byte[])}.
     * You as a client are responsible to provide first input
     *
     * @param input1Length expected length of first inputs
     */
    public ConcatAlgorithm(int input1Length) {
        if (input1Length < 0) {
            throw new IllegalArgumentException("Input length must be greater than 0");
        }
        this.input1Length = input1Length;
    }

    @Override
    public byte[] combine(byte[] input1, byte[] input2) {
        if (input1Length != INPUT_LENGTH_NOT_SET && input1Length != input1.length) { // only if input1Length is set
            throw new IllegalArgumentException("Length of first input must be " + input1Length);
        }
        byte[] out = new byte[input1.length + input2.length];
        System.arraycopy(input1, 0, out, 0, input1.length);
        System.arraycopy(input2, 0, out, input1.length, input2.length);
        return out;
    }

    @Override
    public byte[][] split(byte[] combined) {
        if (input1Length == INPUT_LENGTH_NOT_SET) {
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
