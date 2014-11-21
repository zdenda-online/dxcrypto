package cz.d1x.crypto.hash;

import cz.d1x.crypto.hash.impl.SHA512;

/**
 * Tests {@link SHA512} implementation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SHA512Test extends HashingAlgorithmTest {

    @Override
    protected HashingAlgorithm getAlgorithm() {
        return new SHA512();
    }

    @Override
    protected String[] getExpectedSimpleOutputs() {
        return new String[] {
                "45363693f7542f64eb438a3185137c2c712dc8aa1ff8a999464d72042bd509902f10361b7d7a8526737ff078b04a338cfd85c63d9f2e114c3f2727da9f63f203",
                "ce32ba6e50c5c73042fbad3e3d8882812f3e8e5857a35ea2239a1e3b57adb127de442f215c92495b26ba01a83496f03b0a07ea801eb8a351c72bdf461f3f2de4",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        };
    }

    @Override
    protected String[] getRepeatedOutputs() {
        return new String[] {
                "fc7bd1c0dabcf9e601ebdbcca41cb2f9afac276852e339fa973ab0e168e03f730f2bcca09df6ef5f959f956aaafdbfd36dec25fb24db9e653d96d30725488f19",
                "c44508895aa84f90661fe790d073cdfedea029f1f843337d573609e8b5d6f7ac8518cc2bd74e96773e0ba83dc7451b739b24221857a2f363192a81616f009e1e",
                "111b55a07597cabe04996109644c0d119175f935c42d254eea56b0b0360fa630ef5f4344512827117f9020dd3d8277ce4efc9ad7dad075d99813ec50896582d2",
        };
    }
}
