package cz.d1x.dxcrypto.hash;

/**
 * Builder that builds {@link DigestAlgorithm} instances.
 * You should use {@link HashingAlgorithms} factory for creating instances.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public final class DigestAlgorithmBuilder extends HashingAlgorithmBuilder {

    private final String algorithmName;

    protected DigestAlgorithmBuilder(String algorithmName) {
        super();
        this.algorithmName = algorithmName;
    }

    @Override
    public HashingAlgorithm build() {
        return new DigestAlgorithm(algorithmName, bytesRepresentation, encoding);
    }
}
