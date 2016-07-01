package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Combining;
import cz.d1x.dxcrypto.common.ConcatAlgorithm;

/**
 * Builder for salted hashing algorithm that is based on existing hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class SaltingAdapterBuilder {

    private final HashingAlgorithm hashingAlgorithm;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    private Combining inputSaltCombining = new ConcatAlgorithm();

    /**
     * Creates a new builder for salting adapter with given hashing algorithm.
     *
     * @param hashingAlgorithm    hashing algorithm to be set
     * @param bytesRepresentation bytes representation of adapted hashing algorithm
     * @param encoding            encoding of adapted hashing algorithm
     */
    public SaltingAdapterBuilder(HashingAlgorithm hashingAlgorithm, BytesRepresentation bytesRepresentation, String encoding) {
        this.hashingAlgorithm = hashingAlgorithm;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;
    }

    /**
     * Sets a custom algorithm for combining input text and salt.
     *
     * @param combining combine algorithm
     * @return this instance
     * @throws IllegalArgumentException exception if passed Combining is null
     */
    public SaltingAdapterBuilder inputAndSaltCombining(Combining combining) {
        if (combining == null) {
            throw new IllegalArgumentException("You must provide non-null Combining!");
        }
        this.inputSaltCombining = combining;
        return this;
    }

    /**
     * Builds a salting adapter with hashing algorithm inside.
     *
     * @return salting adapter
     */
    public SaltedHashingAlgorithm build() {
        return new SaltingAdapter(hashingAlgorithm, bytesRepresentation, inputSaltCombining, encoding);
    }
}
