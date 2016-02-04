package cz.d1x.dxcrypto.encryption;

import org.junit.Assert;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tests {@link EncryptionAlgorithm} implementations.
 * Note that it tests only basic scenarios with default encoding (as it calls other encrypt/decrypt methods).
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class EncryptionAlgorithmsTest {

    private static final byte[] AES_KEY = {
            0x27, 0x18, 0x27, 0x09, 0x7C, 0x44, 0x17, 0x1E,
            0x43, 0x03, 0x11, 0x27, 0x1F, 0x0D, 0x6D, 0x64};
    private static final byte[] TRIPLE_DES_KEY = {
            0x27, 0x18, 0x27, 0x09, 0x7C, 0x44, 0x17, 0x1E,
            0x43, 0x03, 0x11, 0x27, 0x1F, 0x0D, 0x6D, 0x64,
            0x44, 0x18, 0x27, 0x09, 0x7A, 0x44, 0x17, 0x3E};
    private static final KeyPair RSA_KEYS = new RSAKeysGenerator().generateKeys();

    protected List<EncryptionAlgorithm> getImplementationsToTest() {
        return new ArrayList<EncryptionAlgorithm>() {{
            add(EncryptionAlgorithms.aes(AES_KEY).build());
            add(EncryptionAlgorithms.tripleDes(TRIPLE_DES_KEY).build());
            add(EncryptionAlgorithms.rsa().keyPair(RSA_KEYS).build());

            BigInteger modulus = ((RSAPublicKey) RSA_KEYS.getPublic()).getModulus();
            BigInteger publicExponent = ((RSAPublicKey) RSA_KEYS.getPublic()).getPublicExponent();
            BigInteger privateExponent = ((RSAPrivateKey) RSA_KEYS.getPrivate()).getPrivateExponent();
            add(EncryptionAlgorithms.rsa()
                    .publicKey(modulus, publicExponent)
                    .privateKey(modulus, privateExponent)
                    .build());
        }};
    }

    /**
     * Tests encryption of string null.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullStringEncryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            encryptionAlgorithm.encrypt((String) null);
        }
    }

    /**
     * Tests decryption of string null.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullStringDecryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            encryptionAlgorithm.decrypt((String) null);
        }
    }

    /**
     * Tests encryption of string null.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullByteEncryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            encryptionAlgorithm.encrypt((byte[]) null);
        }
    }

    /**
     * Tests decryption of string null.
     */
    @Test(expected = IllegalArgumentException.class)
    public void nullByteDecryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            encryptionAlgorithm.decrypt((byte[]) null);
        }
    }

    /**
     * Tests encryption and decryption of byte methods.
     */
    @Test
    public void byteBasedEncryption() throws UnsupportedEncodingException {
        String plain = "th1s_is_something inter3sting -*";
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            byte[] plainBytes = plain.getBytes("UTF-8");
            byte[] encryptedBytes = encryptionAlgorithm.encrypt(plainBytes);
            byte[] decryptedBytes = encryptionAlgorithm.decrypt(encryptedBytes);
            Assert.assertArrayEquals("Original and decrypted strings are not equal", plainBytes, decryptedBytes);
        }
    }

    /**
     * Tests encryption and decryption of string methods.
     */
    @Test
    public void stringBasedEncryption() throws UnsupportedEncodingException {
        String plain = "th1s_is_something inter3sting -*";
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            String encrypted = encryptionAlgorithm.encrypt(plain);
            String decrypted = encryptionAlgorithm.decrypt(encrypted);
            Assert.assertNotEquals("Plain and encrypted strings are not different", plain, encrypted);
            Assert.assertEquals("Original and decrypted strings are not equal", plain, decrypted);
        }
    }

    /**
     * Tests whether encryption and decryption works if different instances with same key are used for each operation.
     */
    @Test
    public void differentInstanceWithSameKeyGiveSameResults() throws UnsupportedEncodingException {
        List<EncryptionAlgorithm> encryptionAlgorithms1 = getImplementationsToTest();
        List<EncryptionAlgorithm> encryptionAlgorithms2 = getImplementationsToTest();

        String plain = "th1s_is_something inter3sting -*";
        for (int i = 0; i < encryptionAlgorithms1.size(); i++) {
            EncryptionAlgorithm alg1 = encryptionAlgorithms1.get(i);
            EncryptionAlgorithm alg2 = encryptionAlgorithms2.get(i);

            byte[] plainBytes = plain.getBytes("UTF-8");
            byte[] encryptedBytes = alg1.encrypt(plainBytes);
            byte[] decryptedBytes = alg2.decrypt(encryptedBytes); // using different instance but same key for decrypt
            Assert.assertArrayEquals("Original and decrypted strings are not equal", plainBytes, decryptedBytes);
        }
    }

    /**
     * Tests whether encryption via symmetric algorithm gives different result for same input (thanks to IV).
     */
    @Test
    public void sameInputsGiveDifferentResultsForSymmetricAlgorithms() throws UnsupportedEncodingException {
        String plain = "th1s_is_something inter3sting -*";
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            if (!(encryptionAlgorithm instanceof SymmetricCryptoAlgorithm)) {
                continue; // test only symmetric algorithms
            }
            String encrypted1 = encryptionAlgorithm.encrypt(plain);
            String encrypted2 = encryptionAlgorithm.encrypt(plain);
            Assert.assertNotEquals(encrypted1, encrypted2);

            String encrypted1End = encrypted1.substring(40);
            String encrypted2End = encrypted2.substring(40);
            Assert.assertNotEquals(encrypted1End, encrypted2End);
        }
    }

    /**
     * Tests compatibility between byte and string methods.
     * To be precise when encryption is made using byte method and decryption by string method.
     */
    @Test
    public void byteAndStringBasedMethodsGiveSameOutput() throws UnsupportedEncodingException {
        String plainString = "Som3 T@";
        byte[] plainBytes = new byte[]{'S', 'o', 'm', '3', ' ', 'T', '@'};
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            byte[] encrypted = encryptionAlgorithm.encrypt(plainBytes);
            String decrypted = encryptionAlgorithm.decrypt(DatatypeConverter.printHexBinary(encrypted).toLowerCase());
            Assert.assertEquals("Original and decrypted strings are not equal", plainString, decrypted);
        }
    }

    /**
     * Tests concurrent encryption from multiple threads (immutability of algorithm instance).
     */
    @Test
    public void testConcurrentEncryption() {
        int threads = 1000;
        final AtomicBoolean everythingOk = new AtomicBoolean(true);
        final AtomicInteger finishedThreads = new AtomicInteger(0);

        for (final EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            for (int i = 0; i < threads; i++) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            final byte[] origInput = new byte[30];
                            new Random().nextBytes(origInput);
                            byte[] output = encryptionAlgorithm.encrypt(origInput);
                            byte[] input = encryptionAlgorithm.decrypt(output);
                            if (input != origInput) {
                                everythingOk.set(false);
                            }
                        } catch (Exception ex) {
                            System.out.println("Concurrent encryption fails!");
                            everythingOk.set(false);
                        }
                        finishedThreads.incrementAndGet();
                    }
                });
                thread.start();
            }
        }

        while (finishedThreads.get() < threads) {
            try {
                Thread.sleep(100);
                if (!everythingOk.get()) {
                    Assert.fail("Any of hashing failed");
                }
            } catch (InterruptedException e) {
                Assert.fail("Interrupted thread in test");
            }
        }
    }
}
