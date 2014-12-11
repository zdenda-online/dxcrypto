package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.Encoding;
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
    private CombineAlgorithm combineAlgorithm;
    private String encoding;

    /**
     * Creates a new builder for salting adapter with given hashing algorithm.
     *
     * @param hashingAlgorithm hashing algorithm to be set
     */
    public SaltingAdapterBuilder(HashingAlgorithm hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
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
     * Sets encoding for strings in input and output.
     *
     * @param encoding encoding to be set
     * @return this instance
     */
    public SaltingAdapterBuilder encoding(String encoding) {
        this.encoding = encoding;
        return this;
    }

    /**
     * Builds a salting adapter with hashing algorithm inside.
     *
     * @return salting adapter
     */
    public SaltingAdapter build() {
        if (encoding == null) {
            encoding = Encoding.DEFAULT;
        }
        if (combineAlgorithm == null) {
            combineAlgorithm = DEFAULT_COMBINE_ALGORITHM;
        }
        return new SaltingAdapter(hashingAlgorithm, combineAlgorithm, encoding);
    }
}
