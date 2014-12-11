package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.CombineAlgorithm;

/**
 * Builder for repeating decorator over existing hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RepeatingDecoratorBuilder implements HashingAlgorithmBuilder {

    private final HashingAlgorithm hashingAlgorithm;
    private int repeats = -1;

    /**
     * Creates a new builder for repeating decorator with given hashing algorithm.
     *
     * @param hashingAlgorithm hashing algorithm to be set
     */
    public RepeatingDecoratorBuilder(HashingAlgorithm hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
    }

    /**
     * Sets repeats for repeating decorator.
     *
     * @param repeats repeats to be set
     * @return this instance
     */
    public RepeatingDecoratorBuilder repeats(int repeats) {
        if (repeats < 1) {
            throw new IllegalArgumentException("Expecting at least 1 repeat");
        }
        this.repeats = repeats;
        return this;
    }

    /**
     * Builds a repeating decorator and wraps it by salting adapter builder.
     *
     * @return salting adapter builder
     */
    public SaltingAdapterBuilder salted() {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg);
    }

    /**
     * Builds a repeating decorator and wraps it by salting adapter builder with custom combine algorithm.
     *
     * @param combineAlgorithm combine algorithm for input text and salt
     * @return salting adapter builder
     */
    public SaltingAdapterBuilder salted(CombineAlgorithm combineAlgorithm) {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg)
                .combineAlgorithm(combineAlgorithm);
    }

    @Override
    public RepeatingDecorator build() {
        return new RepeatingDecorator(hashingAlgorithm, repeats);
    }
}
