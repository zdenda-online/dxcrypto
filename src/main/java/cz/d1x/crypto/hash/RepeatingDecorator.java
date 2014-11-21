package cz.d1x.crypto.hash;

/**
 * Decorator for {@link HashingAlgorithm} implementations which repeats hashing algorithm multiple times.
 * E.g. hash(hash(hash(input)))
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class RepeatingDecorator implements HashingAlgorithm {

    private final HashingAlgorithm hashingAlgorithm;
    private final int repeatsCount;

    /**
     * Creates a new repeating decorator with specified algorithm a repeats count.
     *
     * @param hashingAlgorithm algorithm to be repeated
     * @param repeatsCount     number of repeats of hashing
     */
    public RepeatingDecorator(HashingAlgorithm hashingAlgorithm, int repeatsCount) {
        if (hashingAlgorithm == null) {
            throw new IllegalArgumentException("Expecting non-null decorated algorithm");
        }
        this.hashingAlgorithm = hashingAlgorithm;

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
    @Override
    public String hash(String input) {
        return repeat(hashingAlgorithm.hash(input));
    }

    /**
     * {@inheritDoc}
     * <p/>
     * Repeats algorithm by specified number of times.
     */
    @Override
    public byte[] hash(byte[] input) throws HashingException {
        return repeat(hashingAlgorithm.hash(input));
    }

    /**
     * Repeats algorithm of hashing for {@link String} inputs.
     *
     * @param text input text to be repeated
     * @return repeated hashing output
     */
    private String repeat(String text) {
        for (int i = 0; i < repeatsCount - 1; i++) {
            text = hashingAlgorithm.hash(text);
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
            input = hashingAlgorithm.hash(input);
        }
        return input;
    }
}
