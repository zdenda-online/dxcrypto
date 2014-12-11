package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.props.SecureProperties;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.StringWriter;

/**
 * Tests encrypted properties extension
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SecurePropertiesTest {

    private final EncryptionAlgorithm algorithm = EncryptionAlgorithms.aes("mySuperKey")
            .keySalt("andSuperS@lt")
            .build();

    @Test(expected = IllegalArgumentException.class)
    public void nullEncryptionPrefix() {
        new SecureProperties(algorithm, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyPrefix() {
        new SecureProperties(algorithm, "");
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyTrimmedPrefix() {
        new SecureProperties(algorithm, " \t ");
    }

    @Test
    public void nonEncryptedPropertyDefaultPrefix() {
        SecureProperties props = new SecureProperties(algorithm);
        props.setProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void nonEncryptedPropertyCustomPrefix() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void encryptedPropertyDefaultPrefix() {
        EncryptionAlgorithm algorithm = this.algorithm;
        SecureProperties props = new SecureProperties(algorithm);
        props.setEncryptedProperty("foo", "bar"); // bar value is stored encrypted
        String actual = props.getProperty("foo"); // if property is encrypted, it gets automatically decrypted
        // actual == "bar"
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void encryptedPropertyCustomPrefix() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setEncryptedProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void validateItIsEncryptedInside() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setEncryptedProperty("foo", "bar");
        String encryptedValue = props.getOriginalProperty("foo");
        Assert.assertTrue(encryptedValue.endsWith("--mySuffix"));
        String encryptedValueNoSuffix = encryptedValue.substring(0, encryptedValue.length() - "--mySuffix".length());
        Assert.assertEquals(64, encryptedValueNoSuffix.length()); // 32 bytes of data
    }

    @Test
    public void validateItIsEncryptedWhenStored() throws IOException {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setEncryptedProperty("foo", "bar");

        StringWriter sw = new StringWriter();
        props.store(sw, null);
        String[] propsStrings = sw.toString().split("\n");
        Assert.assertTrue(propsStrings.length >= 2);
        Assert.assertTrue(propsStrings[1].endsWith("--mySuffix"));
        String encryptedValue = propsStrings[1].substring(0, propsStrings[1].length() - "foo=--mySuffix".length());
        Assert.assertEquals(64, encryptedValue.length()); // 32 bytes of data
    }
}
