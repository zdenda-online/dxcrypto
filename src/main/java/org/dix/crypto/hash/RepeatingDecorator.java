package org.dix.crypto.hash;

/**
 * Decorator for {@link HashingAlgorithm} implementations which repeats hashing algorithm multiple times.
 * E.g. hash(hash(hash(input)))
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RepeatingDecorator implements HashingAlgorithm {

    private final HashingAlgorithm decoratedAlgorithm;
    private final int repeatsCount;

    /**
     * Creates a new repeating decorator with specified algorithm a repeats count.
     *
     * @param repeatedAlgorithm algorithm to be repeated
     * @param repeatsCount      number of repeats of hashing
     */
    public RepeatingDecorator(HashingAlgorithm repeatedAlgorithm, int repeatsCount) {
        this.decoratedAlgorithm = repeatedAlgorithm;
        if (repeatsCount < 1) {
            throw new IllegalArgumentException("Expecting at least 1 repeat");
        }
        this.repeatsCount = repeatsCount;
    }

    /**
     * {@inheritDoc}
     * <p/>
     * Repeats algorithm by specified number of times.
     */
    public String hash(String text) {
        return repeat(decoratedAlgorithm.hash(text));
    }

    /**
     * {@inheritDoc}
     * <p/>
     * Repeats algorithm by specified number of times.
     */
    @Override
    public byte[] hash(byte[] bytes) throws HashingException {
        return repeat(decoratedAlgorithm.hash(bytes));
    }

    /**
     * {@inheritDoc}
     * <p/>
     * It is encoding of decorated algorithm.
     */
    @Override
    public String getEncoding() {
        return decoratedAlgorithm.getEncoding();
    }

    /**
     * Repeats algorithm of hashing for {@link String} inputs.
     *
     * @param text input text to be repeated
     * @return repeated hashing output
     */
    private String repeat(String text) {
        for (int i = 0; i < repeatsCount - 1; i++) {
            text = decoratedAlgorithm.hash(text);
        }
        return text;
    }

    /**
     * Repeats algorithm of hashing for byte array inputs.
     *
     * @param input input to be repeated
     * @return repeated hashing output
     */
    private byte[] repeat(byte[] input) {
        for (int i = 0; i < repeatsCount - 1; i++) {
            input = decoratedAlgorithm.hash(input);
        }
        return input;
    }
}
