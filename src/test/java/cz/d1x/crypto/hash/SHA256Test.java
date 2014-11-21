package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.impl.SHA256;

/**
 * Tests {@link SHA256} implementation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA256Test extends HashingAlgorithmTest {

    @Override
    protected HashingAlgorithm getAlgorithm() {
        return new SHA256();
    }

    @Override
    protected String[] getExpectedSimpleOutputs() {
        return new String[] {
                "26acaf5d1ecdbf7cf93d8da58093c67814dfb61e86caaf439faedbc321d7cb16",
                "8647cbb8fbf7a6ac48f117adafbb0110d337655a6d2d7246c04be455ec59f4dc",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        };
    }

    @Override
    protected String[] getRepeatedOutputs() {
        return new String[] {
                "c49ea2b2215df674e2c4d22d7ff0ee975f1f7997e8f893e73921141369d0994b",
                "127edc94a89bc17255acbd01e161db33e1afcf8f3fdb71e296e87b919d06eff2",
                "e67e72111b363d80c8124d28193926000980e1211c7986cacbd26aacc5528d48"
        };
    }
}
