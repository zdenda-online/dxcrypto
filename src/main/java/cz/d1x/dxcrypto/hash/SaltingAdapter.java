package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.ConcatCombineAlgorithm;
import cz.d1x.dxcrypto.common.Encoding;

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
public class SaltingAdapter implements SaltedHashingAlgorithm {

    private final HashingAlgorithm hashingAlgorithm;
    private final CombineAlgorithm combineAlgorithm;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm    algorithm for hashing
     * @param bytesRepresentation representation of bytes
     * @param combineAlgorithm    strategy how to combine input text and salt
     * @param encoding            encoding for used strings
     */
    protected SaltingAdapter(HashingAlgorithm hashingAlgorithm, BytesRepresentation bytesRepresentation,
                             CombineAlgorithm combineAlgorithm, String encoding) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null adapted algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

        if (combineAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null combine strategy");
        }
        this.combineAlgorithm = combineAlgorithm;
        this.bytesRepresentation = bytesRepresentation;

        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
    }

    @Override
    public String hash(String input, String salt) throws HashingException {
        byte[] inputBytes = Encoding.getBytes(input, encoding);
        byte[] saltBytes = Encoding.getBytes(salt, encoding);
        byte[] hashed = hash(inputBytes, saltBytes);
        return bytesRepresentation.toString(hashed);
    }

    @Override
    public byte[] hash(byte[] input, byte[] salt) throws HashingException {
        byte[] toHash = combineAlgorithm.combine(input, salt);
        return hashingAlgorithm.hash(toHash);
    }
}
