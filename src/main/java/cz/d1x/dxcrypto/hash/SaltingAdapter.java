package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Combining;
import cz.d1x.dxcrypto.common.Encoding;

/**
 * <p>
 * Adapter for hashing algorithms that combines input text and salt before it is processed by adapted algorithm.
 * For combination, you can implement your own {@link Combining} or you can use default one.
 * </p>
 * Example:
 * <pre>
 *     HashingAlgorithm sha256 = new SHA256();
 *     SaltingAdapter adapter = new SaltingAdapter(alg); // ConcatCombineAlgorithm
 *     adapter.hash("your input text", "your salt");
 *
 *     // or with custom combine algorithm
 *     Combining combineAlg = ...; // your implementation
 *     SaltingAdapter adapter = new SaltingAdapter(alg, combineAlg); // ConcatCombineAlgorithm
 * </pre>
 * <p>
 * Be sure to store the salt along with the hash for future checks.
 * </p>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see cz.d1x.dxcrypto.common.ConcatAlgorithm
 */
public final class SaltingAdapter implements SaltedHashingAlgorithm {

    private final HashingAlgorithm hashingAlgorithm;
    private final Combining inputSaltCombining;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    /**
     * Creates a new salting adapter.
     *
     * @param hashingAlgorithm    algorithm for hashing
     * @param bytesRepresentation representation of bytes
     * @param inputSaltCombining  strategy how to combine input text and salt
     * @param encoding            encoding for used strings
     */
    protected SaltingAdapter(HashingAlgorithm hashingAlgorithm, BytesRepresentation bytesRepresentation,
                             Combining inputSaltCombining, String encoding) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null adapted algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

        if (inputSaltCombining == null) {
            throw new IllegalArgumentException("Expecting non-null combine strategy");
        }
        this.inputSaltCombining = inputSaltCombining;
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
        byte[] toHash = inputSaltCombining.combine(input, salt);
        return hashingAlgorithm.hash(toHash);
    }
}
