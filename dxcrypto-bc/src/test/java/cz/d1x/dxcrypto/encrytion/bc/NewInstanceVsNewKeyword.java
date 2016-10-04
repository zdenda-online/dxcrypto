package cz.d1x.dxcrypto.encrytion.bc;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.Test;

/**
 * Tests performance of .newInstance instead of new operator to check whether BC implementation performance.
 */
public class NewInstanceVsNewKeyword {

    @Test
    public void newInstanceVsNewKeyword() throws IllegalAccessException, InstantiationException {

        // warm-up only
        Class<? extends BlockCipher> clazz = AESEngine.class;
        for (int i = 0; i < 1000; i++) {
            clazz.newInstance();
            new AESEngine();
        }

        int testsCount = 100000;
        int newInstFaster = 0, newOpFaster = 0;
        long newInstAddedTime = 0, newOpAddedTime = 0;
        for (int i = 0; i < testsCount; i++) {
            long newInstStart = System.nanoTime();
            clazz.newInstance();
            long newInstDuration = System.nanoTime() - newInstStart;

            long newOpStart = System.nanoTime();
            new AESEngine();
            long newOpDuration = System.nanoTime() - newOpStart;

            if (newInstDuration > newOpDuration) {
                newOpFaster++;
                newInstAddedTime += newInstDuration - newOpDuration;
            } else if (newInstDuration < newOpDuration) {
                newInstFaster++;
                newOpAddedTime += newOpDuration - newInstDuration;
            }
        }

        int newInstFasterPercent = (newInstFaster * 100) / testsCount;
        int newOpFasterPercent = (newOpFaster * 100) / testsCount;
        long avgNewInst = newInstAddedTime / newOpFaster;
        long avgNewOp = newOpAddedTime / newInstFaster;
        System.out.println(".newInstance() was faster in " + newInstFaster + " tests (~" + newInstFasterPercent + "%), " +
                "new keyword took additional " + avgNewOp + " nanos on average");
        System.out.println("new keyword was faster in " + newOpFaster + " tests (~" + newOpFasterPercent + "%), " +
                ".newInstance() took additional " + avgNewInst + " nanos on average");
    }
}
