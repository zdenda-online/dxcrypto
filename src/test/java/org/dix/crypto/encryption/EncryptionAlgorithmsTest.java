package org.dix.crypto.encryption;

import org.dix.crypto.encryption.impl.AES;
import org.dix.crypto.encryption.impl.TripleDES;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;

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

    protected Collection<EncryptionAlgorithm> getImplementationsToTest() {
        return new ArrayList<EncryptionAlgorithm>() {{
            add(new AES(AES_KEY));
            add(new TripleDES(TRIPLE_DES_KEY));
        }};
    }

    @Test
    public void bytesEncryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            String plain = "th1s_is_something_inter3sting";
            byte[] plainBytes = plain.getBytes("UTF-8");
            byte[] encryptedBytes = encryptionAlgorithm.encrypt(plainBytes);
            byte[] decryptedBytes = encryptionAlgorithm.decrypt(encryptedBytes);
            Assert.assertArrayEquals("Original and decrypted strings are not equal", plainBytes, decryptedBytes);
        }
    }

    @Test
    public void basicEncryption() throws UnsupportedEncodingException {
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            String plain = "th1s_is_something_inter3sting";
            String encrypted = encryptionAlgorithm.encrypt(plain);
            String decrypted = encryptionAlgorithm.decrypt(encrypted);
            Assert.assertNotEquals("Plain and encrypted strings are not different", plain, encrypted);
            Assert.assertEquals("Original and decrypted strings are not equal", plain, decrypted);
            System.out.println(plain + " -> " + encrypted + " -> " + decrypted);
        }
    }
}
