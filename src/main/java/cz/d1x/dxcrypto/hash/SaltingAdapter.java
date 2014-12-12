package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.ConcatCombineAlgorithm;

/**
 * <p>
 * Adapter for hashing algorithms that combines input text and salt before it is processed by adapted algorithm.
 * For combination, you can implement your own {@link CombineAlgorithm} or you can use default one.
 * </p>
 * Example:
 * <pre>
 *     HashingAlgorithm sha256 = new SHA256();
 *     SaltingAdapter adapter = new SaltingAdapter(alg); // ConcatCombineAlgorithm
 *     adapter.hash("your input text", "your salt");
 *
 *     // or with custom combine algorithm
 *     CombineAlgorithm combineAlg = ...; // your implementation
 *     SaltingAdapter adapter = new SaltingAdapter(alg, combineAlg); // ConcatCombineAlgorithm
 * </pre>
 * <p>
 * Be sure to store the salt along with the hash for future checks.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see ConcatCombineAlgorithm
 */
public class SaltingAdapter {


    private final HashingAlgorithm hashingAlgorithm;
    private final CombineAlgorithm combineAlgorithm;
    private final String encoding;

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm algorithm for hashing
     * @param combineAlgorithm strategy how to combine input text and salt
     * @param encoding         encoding for used strings
     */
    protected SaltingAdapter(HashingAlgorithm hashingAlgorithm, CombineAlgorithm combineAlgorithm, String encoding) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null adapted algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

        if (combineAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null combine strategy");
        }
        this.combineAlgorithm = combineAlgorithm;

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
        byte[] toHash = combineAlgorithm.combine(inputBytes, saltBytes);
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
        byte[] toHash = combineAlgorithm.combine(input, salt);
        return hashingAlgorithm.hash(toHash);
    }
}
