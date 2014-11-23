package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.digest.MD5;

/**
 * Tests {@link MD5} implementation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class MD5Test extends HashingAlgorithmTest {

    @Override
    protected HashingAlgorithm getAlgorithm() {
        return new MD5();
    }

    @Override
    protected String[] getExpectedSimpleOutputs() {
        return new String[] {
                "72f1916f84bb839e965209632f0f5d16",
                "012e42a666b86204e77331c0ebb720be",
                "d41d8cd98f00b204e9800998ecf8427e"
        };
    }

    @Override
    protected String[] getRepeatedOutputs() {
        return new String[] {
                "dd98b64722d9dd1d8d46641d33cdd7ed",
                "349d4684c56c8edcfc329d14cf683e5f",
                "acf7ef943fdeb3cbfed8dd0d8f584731",
        };
    }
}
