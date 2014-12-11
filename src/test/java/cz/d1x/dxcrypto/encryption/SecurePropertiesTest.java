package cz.d1x.dxcrypto.encryption;

import cz.d1x.dxcrypto.props.SecureProperties;
import org.junit.Assert;
import org.junit.Test;

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
        SecureProperties props = new SecureProperties(algorithm, "--myPrefix");
        props.setProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void encryptedPropertyDefaultPrefix() {
        SecureProperties props = new SecureProperties(algorithm);
        props.setEncryptedProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void encryptedPropertyCustomPrefix() {
        SecureProperties props = new SecureProperties(algorithm, "--myPrefix");
        props.setEncryptedProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }
}
