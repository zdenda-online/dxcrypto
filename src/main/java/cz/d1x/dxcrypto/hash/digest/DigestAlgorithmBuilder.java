package cz.d1x.dxcrypto.hash.digest;

import cz.d1x.dxcrypto.Encoding;
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

    private String encoding;

    protected DigestAlgorithmBuilder() {
    }

    /**
     * Gets a name of algorithm supported by digest.
     *
     * @return algorithm name
     */
    protected abstract String getAlgorithm();

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
     * Builds a hashing algorithm and wraps it into salting adapter builder.
     *
     * @return salting adapter
     */
    public SaltingAdapterBuilder salted() {
        HashingAlgorithm alg = build();
        return new SaltingAdapterBuilder(alg, encoding);
    }

    /**
     * Builds a hashing algorithm and wraps it into repeating decorator builder.
     *
     * @param repeats count of repeats
     * @return repeating decorator
     */
    public RepeatingDecoratorBuilder repeated(int repeats) {
        HashingAlgorithm alg = build();
        return new RepeatingDecoratorBuilder(alg)
                .repeats(repeats);
    }

    @Override
    public HashingAlgorithm build() throws EncryptionException {
        if (encoding == null) {
            encoding = Encoding.UTF_8;
        }
        return new DigestAlgorithm(getAlgorithm(), encoding);
    }
}
