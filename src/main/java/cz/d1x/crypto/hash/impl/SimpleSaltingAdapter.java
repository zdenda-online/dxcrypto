package cz.d1x.crypto.hash.impl;

import cz.d1x.crypto.hash.HashingAlgorithm;
import cz.d1x.crypto.hash.SaltingAdapter;

/**
 * Simple adapter of {@link HashingAlgorithm} implementations which concatenates text and salt before hashing
 * by putting one byte between them.
 * <p/>
 * Be sure to store the salt along with the hash for future checks.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SaltingAdapter
 */
public class SimpleSaltingAdapter extends SaltingAdapter {

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm used for hashing
     */
    public SimpleSaltingAdapter(HashingAlgorithm hashingAlgorithm) {
        super(hashingAlgorithm);
    }

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm used for hashing
     * @param encoding         encoding used for strings
     */
    public SimpleSaltingAdapter(HashingAlgorithm hashingAlgorithm, String encoding) {
        super(hashingAlgorithm, encoding);
    }

    @Override
    protected byte[] concatenate(byte[] input, byte[] salt) {
        byte[] out = new byte[input.length + salt.length + 1]; // 1 byte between input and salt
        System.arraycopy(input, 0, out, 0, input.length);
        out[input.length] = 0x27; // my favourite number:-)
        System.arraycopy(salt, 0, out, input.length + 1, salt.length);
        return out;
    }
}
