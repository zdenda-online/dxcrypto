package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.Encoding;

/**
 * Adapter for hashing algorithms that concatenates input text and salt before it is processed by adapted algorithm.
 * For concatenation, you can implement your own {@link ConcatStrategy} or you can use default one.
 * <p/>
 * Example:
 * <pre>
 *     HashingAlgorithm sha256 = new SHA256();
 *     SaltingAdapter adapter = new SaltingAdapter(alg); // DefaultConcatStrategy
 *     adapter.hash("your input text", "your salt");
 * </pre>
 * <p/>
 * Be sure to store the salt along with the hash for future checks.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see DefaultConcatStrategy
 */
public class SaltingAdapter {

    private static final ConcatStrategy DEFAULT_CONCAT_STRATEGY = new DefaultConcatStrategy();

    private final HashingAlgorithm hashingAlgorithm;
    private final ConcatStrategy concatStrategy;
    private final String encoding;

    /**
     * Creates a new salting adapter.
     * {@link DefaultConcatStrategy} will be used for input text and salt concatenation.
     * {@link Encoding#UTF_8} will be used for strings.
     *
     * @param hashingAlgorithm algorithm used for hashing
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm) {
        this(hashingAlgorithm, DEFAULT_CONCAT_STRATEGY, Encoding.UTF_8);
    }

    /**
     * Creates a new salting adapter.
     * {@link DefaultConcatStrategy} will be used for input text and salt concatenation.
     *
     * @param hashingAlgorithm algorithm used for hashing
     * @param encoding         encoding used for strings
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm, String encoding) {
        this(hashingAlgorithm, DEFAULT_CONCAT_STRATEGY, encoding);
    }

    /**
     * Creates a new salting adapter.
     * {@link Encoding#UTF_8} will be used for strings.
     *
     * @param hashingAlgorithm algorithm for hashing
     * @param concatStrategy   strategy how to concatenate input text and salt
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm, ConcatStrategy concatStrategy) {
        this(hashingAlgorithm, concatStrategy, Encoding.UTF_8);
    }

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm for hashing
     * @param concatStrategy   strategy how to concatenate input text and salt
     * @param encoding         encoding for used strings
     */
    public SaltingAdapter(HashingAlgorithm hashingAlgorithm, ConcatStrategy concatStrategy, String encoding) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null decorated algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

        if (concatStrategy == null) {
            throw new IllegalArgumentException("Expecting non-null concat strategy");
        }
        this.concatStrategy = concatStrategy;

        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
    }


    /**
     * Hashes given input with given salt using adapted hashing algorithm.
     *
     * @param input input to be hashed
     * @param salt  salt to be added to input
     * @return hashed input
     * @throws HashingException possible exception during hashing
     */
    public String hash(String input, String salt) throws HashingException {
        byte[] inputBytes = Encoding.getBytes(input, encoding);
        byte[] saltBytes = Encoding.getBytes(salt, encoding);
        byte[] toHash = concatStrategy.concatenate(inputBytes, saltBytes);
        return Encoding.getString(hashingAlgorithm.hash(toHash), encoding);
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
        byte[] toHash = concatStrategy.concatenate(input, salt);
        return hashingAlgorithm.hash(toHash);
    }
}
