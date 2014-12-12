package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.Encoding;
import cz.d1x.dxcrypto.common.HexRepresentation;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingAlgorithmBuilder;
import cz.d1x.dxcrypto.hash.RepeatingDecoratorBuilder;
import cz.d1x.dxcrypto.hash.SaltingAdapterBuilder;

/**
 * Base builder for hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 * @see DigestAlgorithm
 */
public abstract class DigestAlgorithmBuilder implements HashingAlgorithmBuilder {

    private BytesRepresentation bytesRepresentation = new HexRepresentation();
    private String encoding = Encoding.DEFAULT;

    protected DigestAlgorithmBuilder() {
    }

    /**
     * Gets a name of algorithm supported by digest.
     *
     * @return algorithm name
     */
    protected abstract String getAlgorithm();

    /**
     * Sets how byte arrays will be represented in strings. By default {@link HexRepresentation} is used.
     *
     * @param bytesRepresentation byte array representation strategy
     * @return this instance
     */
    public DigestAlgorithmBuilder bytesRepresentation(BytesRepresentation bytesRepresentation) {
        this.bytesRepresentation = bytesRepresentation;
        return this;
    }

    /**
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     */
    public DigestAlgorithmBuilder encoding(String encoding) {
        this.encoding = encoding;
        return this;
    }

    /**
     * Builds a hashing algorithm and wraps it by salting adapter builder.
     * Salting adapter automatically gets the same encoding as hashing algorithm.
     *
     * @return salting adapter builder
     */
    public SaltingAdapterBuilder salted() {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg)
                .encoding(encoding);
    }

    /**
     * Builds a hashing algorithm and wraps it by salting adapter builder with custom combine algorithm.
     * Salting adapter automatically gets the same encoding as hashing algorithm.
     *
     * @param combineAlgorithm combine algorithm for input text and salt
     * @return salting adapter builder
     */
    public SaltingAdapterBuilder salted(CombineAlgorithm combineAlgorithm) {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg)
                .combineAlgorithm(combineAlgorithm)
                .encoding(encoding);
    }

    /**
     * Builds a hashing algorithm and wraps it into repeating decorator builder.
     *
     * @param repeats count of repeats
     * @return repeating decorator builder
     */
    public RepeatingDecoratorBuilder repeated(int repeats) {
        HashingAlgorithm alg = build();
        return new RepeatingDecoratorBuilder(alg)
                .repeats(repeats);
    }

    @Override
    public HashingAlgorithm build() throws EncryptionException {
        return new DigestAlgorithm(getAlgorithm(), bytesRepresentation, encoding);
    }
}
