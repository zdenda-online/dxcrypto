package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Combining;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.common.HexRepresentation;

/**
 * Base builder for all hashing algorithms.
 * You should use {@link HashingAlgorithms} factory for creating instances.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see DigestAlgorithm
 */
public abstract class HashingAlgorithmBuilder {

    protected BytesRepresentation bytesRepresentation = new HexRepresentation();
    protected String encoding = Encoding.DEFAULT;

    protected HashingAlgorithmBuilder() {
    }

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     * @throws IllegalArgumentException exception if passed key BytesRepresentation is null
     */
    public HashingAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) throws IllegalArgumentException {
        if (bytesRepresentation == null) {
            throw new IllegalArgumentException("You must provide non-null BytesRepresentation!");
        }
        this.bytesRepresentation = bytesRepresentation;
        return this;
    }

    /**
     * Sets encoding for strings of input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     * @throws IllegalArgumentException exception if given encoding is null or not supported
     */
    public HashingAlgorithmBuilder encoding(String encoding) throws IllegalArgumentException {
        if (encoding == null) {
            throw new IllegalArgumentException("You must provide non-null encoding!");
        }
        Encoding.checkEncoding(encoding);
        this.encoding = encoding;
        return this;
    }

    /**
     * Builds a hashing algorithm and wraps it by salting adapter builder.
     * Salting adapter automatically gets the same encoding as hashing algorithm.
     * <p>
     * Note that you should call this method when you are finished with properties of hashing algorithm.
     * </p>
     *
     * @return salting adapter builder
     */
    public SaltingAdapterBuilder salted() {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg, bytesRepresentation, encoding);
    }

    /**
     * Builds a hashing algorithm and wraps it by salting adapter builder with custom combine algorithm.
     * Salting adapter automatically gets the same encoding as hashing algorithm.
     * <p>
     * Note that you should call this method when you are finished with properties of hashing algorithm.
     * </p>
     *
     * @param combining combine algorithm for input text and salt
     * @return salting adapter builder
     * @throws IllegalArgumentException exception if passed key Combining is null
     */
    public SaltingAdapterBuilder salted(Combining combining) throws IllegalArgumentException {
        if (combining == null) {
            throw new IllegalArgumentException("You must provide non-null Combining!");
        }
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg, bytesRepresentation, encoding)
                .inputAndSaltCombining(combining);
    }

    /**
     * Builds a hashing algorithm and wraps it into repeating decorator builder.
     * <p>
     * Note that you should call this method when you are finished with properties of hashing algorithm.
     * </p>
     *
     * @param repeats count of repeats
     * @return repeating decorator builder
     * @throws IllegalArgumentException exception if passed repeats are lower than 1
     */
    public RepeatingDecoratorBuilder repeated(int repeats) throws IllegalArgumentException {
        if (repeats < 1) {
            throw new IllegalArgumentException("You must provide repeats >= 1!");
        }
        HashingAlgorithm alg = build();
        return new RepeatingDecoratorBuilder(alg, bytesRepresentation, encoding)
                .repeats(repeats);
    }

    /**
     * Builds final hashing algorithm instance.
     *
     * @return hashing algorithm instance
     */
    public abstract HashingAlgorithm build();
}
