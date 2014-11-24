package cz.d1x.dxcrypto.hash;

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
     */
    public RepeatingDecoratorBuilder repeats(int repeats) {
        if (repeats < 1) {
            throw new IllegalArgumentException("Expecting at least 1 repeat");
        }
        this.repeats = repeats;
        return this;
    }

    @Override
    public RepeatingDecorator build() {
        return new RepeatingDecorator(hashingAlgorithm, repeats);
    }
}
