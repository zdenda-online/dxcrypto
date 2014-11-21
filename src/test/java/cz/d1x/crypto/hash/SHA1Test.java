package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.impl.SHA1;

/**
 * Tests {@link SHA1} implementation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA1Test extends HashingAlgorithmTest {

    @Override
    protected HashingAlgorithm getAlgorithm() {
        return new SHA1();
    }

    @Override
    protected String[] getExpectedSimpleOutputs() {
        return new String[] {
                "587fd3e2cd735820c265f64974b46ff3379c4c1a",
                "7fd5fc1920364717c36987057062904539444b88",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        };
    }

    @Override
    protected String[] getRepeatedOutputs() {
        return new String[] {
                "e82052eafc693d9b71089b8200c4cea0f35d59ec",
                "e5c5d3ce2f4f875b73ea757144990bf9ea21c1eb",
                "3e6c06b1a28a035e21aa0a736ef80afadc43122c"
        };
    }
}
