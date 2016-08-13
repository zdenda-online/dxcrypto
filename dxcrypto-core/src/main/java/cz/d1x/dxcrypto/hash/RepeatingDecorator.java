package cz.d1x.dxcrypto.hash;

/**
 * <p>
 * Decorator for hashing algorithms which repeats hashing multiple times.
 * E.g. 3 repeats results in hash(hash(hash(input)))
 * </p>
 * Example:
 * <pre>
 *     HashingAlgorithm sha256 = new SHA256();
 *     HashingAlgorithm decorator = new RepeatingDecorator(alg, 27);
 *     decorator.hash("whateverYouWant");
 * </pre>
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class RepeatingDecorator implements HashingAlgorithm {

    private final HashingAlgorithm hashingAlgorithm;
    private final int repeatsCount;

    /**
     * Creates a new repeating decorator with specified algorithm a repeats count.
     *
     * @param hashingAlgorithm algorithm to be repeated
     * @param repeatsCount     number of repeats of hashing
     */
    protected RepeatingDecorator(HashingAlgorithm hashingAlgorithm, int repeatsCount) {
        this.hashingAlgorithm = hashingAlgorithm;
        this.repeatsCount = repeatsCount;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Repeats algorithm by specified number of times.
     * </p>
     */
    @Override
    public String hash(String input) throws HashingException {
        return repeat(input);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Repeats algorithm by specified number of times.
     * </p>
     */
    @Override
    public byte[] hash(byte[] input) throws HashingException {
        return repeat(input);
    }

    /**
     * Repeats algorithm of hashing for {@link String} inputs.
     *
     * @param text input text to be repeated
     * @return repeated hashing output
     */
    private String repeat(String text) {
        for (int i = 0; i < repeatsCount; i++) {
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
        for (int i = 0; i < repeatsCount; i++) {
            input = hashingAlgorithm.hash(input);
        }
        return input;
    }
}
