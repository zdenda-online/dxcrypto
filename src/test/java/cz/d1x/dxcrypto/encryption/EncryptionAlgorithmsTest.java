package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.encryption.crypto.AES;
import cz.d1x.dxcrypto.encryption.crypto.RSA;
import cz.d1x.dxcrypto.encryption.crypto.RSAKeysGenerator;
import cz.d1x.dxcrypto.encryption.crypto.TripleDES;
import org.junit.Assert;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

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
            add(new AES(AES_KEY));
            add(new TripleDES(TRIPLE_DES_KEY));
            add(new RSA(RSA_KEYS));
        }};
    }

    /**
     * Tests encryption and decryption of byte methods.
     */
    @Test
    public void bytesEncryption() throws UnsupportedEncodingException {
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
    public void stringEncryption() throws UnsupportedEncodingException {
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
    public void sameKeyDifferentInstance() throws UnsupportedEncodingException {
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
     * Tests compatibility between byte and string methods.
     * To be precise when encryption is made using byte method and decryption by string method.
     */
    @Test
    public void sameInstanceDifferentMethod() throws UnsupportedEncodingException {
        String plainString = "Som3 T@";
        byte[] plainBytes = new byte[]{'S', 'o', 'm', '3', ' ', 'T', '@'};
        for (EncryptionAlgorithm encryptionAlgorithm : getImplementationsToTest()) {
            byte[] encrypted = encryptionAlgorithm.encrypt(plainBytes);
            String decrypted = encryptionAlgorithm.decrypt(DatatypeConverter.printHexBinary(encrypted).toLowerCase());
            Assert.assertEquals("Original and decrypted strings are not equal", plainString, decrypted);
        }
    }
}
