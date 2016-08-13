package cz.d1x.dxcrypto.hash;

import cz.d1x.dxcrypto.common.BytesRepresentation;
import cz.d1x.dxcrypto.common.Combining;

/**
 * Builder for repeating decorator over existing hashing algorithms.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class RepeatingDecoratorBuilder {

    private final HashingAlgorithm hashingAlgorithm;
    private final BytesRepresentation bytesRepresentation;
    private final String encoding;
    private int repeats = -1;

    /**
     * Creates a new builder for repeating decorator with given hashing algorithm.
     *
     * @param hashingAlgorithm    hashing algorithm to be set
     * @param bytesRepresentation bytes representation of adapted hashing algorithm
     * @param encoding            encoding of adapted hashing algorithm
     */
    public RepeatingDecoratorBuilder(HashingAlgorithm hashingAlgorithm, BytesRepresentation bytesRepresentation, String encoding) {
        this.hashingAlgorithm = hashingAlgorithm;
        this.bytesRepresentation = bytesRepresentation;
        this.encoding = encoding;
    }

    /**
     * Sets repeats for repeating decorator.
     *
     * @param repeats repeats to be set
     * @return this instance
     * @throws IllegalArgumentException exception if passed repeats are lower than 1
     */
    public RepeatingDecoratorBuilder repeats(int repeats) {
        if (repeats < 1) {
            throw new IllegalArgumentException("You must provide repeats >= 1!");
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
        HashingAlgorithm repeatingDecorator = build();
        return new SaltingAdapterBuilder(repeatingDecorator, bytesRepresentation, encoding);
    }

    /**
     * Builds a repeating decorator and wraps it by salting adapter builder with custom combine algorithm.
     *
     * @param combining combine algorithm for input text and salt
     * @return salting adapter builder
     * @throws IllegalArgumentException exception if passed Combining is null
     */
    public SaltingAdapterBuilder salted(Combining combining) {
        if (combining == null) {
            throw new IllegalArgumentException("You must provide non-null Combining!");
        }
        HashingAlgorithm repeatingDecorator = build();
        return new SaltingAdapterBuilder(repeatingDecorator, bytesRepresentation, encoding)
                .inputAndSaltCombining(combining);
    }

    public RepeatingDecorator build() {
        return new RepeatingDecorator(hashingAlgorithm, repeats);
    }
}
