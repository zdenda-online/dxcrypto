package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.impl.SimpleSaltingAdapter;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * Base adapter of {@link HashingAlgorithm} implementations which concatenates text and salt before hashing.
 * <p/>
 * Implementations should provide only the way how input and salt are concatenated together.
 * <p/>
 * Be sure to store the salt along with the hash for future checks.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see SimpleSaltingAdapter
 */
public abstract class SaltingAdapter {

    private final HashingAlgorithm hashingAlgorithm;
    private final String encoding;

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm used for hashing
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm) {
        this(hashingAlgorithm, HashingAlgorithm.DEFAULT_ENCODING);
    }

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm used for hashing
     * @param encoding         encoding used for strings
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm, String encoding) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null decorated algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

        if (!Charset.isSupported(encoding)) {
            throw new HashingException("Given encoding " + encoding + " is not supported");
        }
        this.encoding = encoding;
    }

    /**
     * Concatenates given input and salt together.
     *
     * @param input input to be concatenated
     * @param salt  salt to be concatenated
     * @return concatenated input and salt
     */
    protected abstract byte[] concatenate(byte[] input, byte[] salt);


    /**
     * Hashes given input with given salt using adapted hashing algorithm.
     *
     * @param input input to be hashed
     * @param salt  salt to be added to input
     * @return hashed input
     * @throws HashingException possible exception during hashing
     */
    public String hash(String input, String salt) throws HashingException {
        try {
            byte[] toHash = concatenate(input.getBytes(encoding), salt.getBytes(encoding));
            return hashingAlgorithm.hash(new String(toHash, encoding));
        } catch (UnsupportedEncodingException e) {
            throw new HashingException(e);
        }
    }

    /**
     * Hashes given input with given salt using adapted hashing algorithm.
     *
     * @param input input to be hashed
     * @param salt  salt to be added to input
     * @return hashed input
     * @throws HashingException possible exception during hashing
     */
    public byte[] hash(byte[] input, byte[] salt) throws HashingException {
        byte[] toHash = concatenate(input, salt);
        return hashingAlgorithm.hash(toHash);
    }
}
