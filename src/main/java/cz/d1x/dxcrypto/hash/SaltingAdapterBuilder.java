package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.ConcatCombineAlgorithm;

/**
 * Builder for salting adapter over existing hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SaltingAdapterBuilder {

    private static final CombineAlgorithm DEFAULT_COMBINE_ALGORITHM = new ConcatCombineAlgorithm();

    private final HashingAlgorithm hashingAlgorithm;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;

    private CombineAlgorithm combineAlgorithm;

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
     * @param combineAlgorithm combine algorithm
     * @return this instance
     */
    public SaltingAdapterBuilder combineAlgorithm(CombineAlgorithm combineAlgorithm) {
        this.combineAlgorithm = combineAlgorithm;
        return this;
    }

    /**
     * Builds a salting adapter with hashing algorithm inside.
     *
     * @return salting adapter
     */
    public SaltingAdapter build() {
        if (combineAlgorithm == null) {
            combineAlgorithm = DEFAULT_COMBINE_ALGORITHM;
        }
        return new SaltingAdapter(hashingAlgorithm, bytesRepresentation, combineAlgorithm, encoding);
    }
}
