package cz.d1x.dxcrypto.performance;

import cz.d1x.dxcrypto.hash.HashingAlgorithms;
import cz.d1x.dxcrypto.hash.SaltedHashingAlgorithm;
import org.junit.Assert;
import org.junit.Test;

import java.util.Random;

/**
 * Tests performance of encryption algorithms in the "common" configuration
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class HashingPerformanceTest {

    private final int ITERATIONS_COUNT = 10 * 1000;
    private final int MIN_PLAIN_TEXT_LENGTH = 10;
    private final int MAX_PLAIN_TEXT_LENGTH = 30;
    private final Random RND = new Random();

    @Test
    public void sha256Performance() {
        SaltedHashingAlgorithm alg = HashingAlgorithms.sha256()
                .salted()
                .build();
        long avg = doTest(alg, "SHA-256");
        // Depends on the machine but I hope I won't get over 50ms on "average" machines where I test
        Assert.assertTrue("Expecting average hashing time lower than 50ms", avg < 50);
    }

    @Test
    public void sha512Performance() {
        SaltedHashingAlgorithm alg = HashingAlgorithms.sha512()
                .salted()
                .build();
        long avg = doTest(alg, "SHA-256");
        // Depends on the machine but I hope I won't get over 50ms on "average" machines where I test
        Assert.assertTrue("Expecting average hashing time lower than 50ms", avg < 50);
    }

    private long doTest(SaltedHashingAlgorithm algorithm, String algName) {
        System.out.println("===> Starting tests of " + algName + " with plain texts of random bytes with length between " +
                "[" + MIN_PLAIN_TEXT_LENGTH + "," + MAX_PLAIN_TEXT_LENGTH + "] and salt length " + 16);
        long minDuration = Long.MAX_VALUE;
        long maxDuration = Long.MIN_VALUE;
        long durationsSum = 0;
        for (int i = 0; i < ITERATIONS_COUNT; i++) {
            int plainTextLength = MIN_PLAIN_TEXT_LENGTH + RND.nextInt(MAX_PLAIN_TEXT_LENGTH - MIN_PLAIN_TEXT_LENGTH);
            byte[] plainText = new byte[plainTextLength];

            byte[] salt = new byte[16];
            RND.nextBytes(salt);

            RND.nextBytes(plainText);
            long start = System.currentTimeMillis();
            algorithm.hash(plainText, salt);
            long duration = System.currentTimeMillis() - start;
            if (duration > maxDuration) {
                maxDuration = duration;
            }
            if (duration < minDuration) {
                minDuration = duration;
            }
            durationsSum += duration;
            // System.out.println(algName + " iteration #" + (i + 1) + " in " + duration + "ms - plain text length: " + plainTextLength);
        }
        long avgDuration = durationsSum / ITERATIONS_COUNT;
        System.out.println("===> Results of algorithm " + algName + ": AVG=" + avgDuration + "ms, MIN=" + minDuration + "ms, MAX=" + maxDuration + "ms");
        return avgDuration;
    }

}
