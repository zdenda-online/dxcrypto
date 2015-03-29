package cz.d1x.dxcrypto.props;

import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithms;
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
    public void nullPrefixThrowsException() {
        new SecureProperties(algorithm, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptySuffixThrowsException() {
        new SecureProperties(algorithm, "");
    }

    @Test(expected = IllegalArgumentException.class)
    public void onlyWhitespacesSuffixThrowsException() {
        new SecureProperties(algorithm, " \t ");
    }

    @Test
    public void nonEncryptedValuesWithDefaultSuffix() {
        SecureProperties props = new SecureProperties(algorithm);
        props.setProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void nonEncryptedValueWithDefaultSuffix() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void nullValuesToBeEncrypted() {
        SecureProperties props = new SecureProperties(algorithm);
        try {
            props.setEncryptedProperty("foo", null);
        } catch (NullPointerException ex) {
            // this is OK, thrown from default Properties implementation
        }
        String actual = props.getProperty("foo");
        Assert.assertNull(actual);
    }

    @Test
    public void emptyValueToBeEncrypted() {
        SecureProperties props = new SecureProperties(algorithm);
        props.setEncryptedProperty("foo", "");
        String actual = props.getProperty("foo");
        Assert.assertTrue(actual.isEmpty());
    }

    @Test
    public void originalPropertyOfNonSetProperty() {
        SecureProperties props = new SecureProperties(algorithm);
        String actual = props.getOriginalProperty("foo");
        Assert.assertNull(actual);
    }

    @Test
    public void getPropertyOfNonSetProperty() {
        SecureProperties props = new SecureProperties(algorithm);
        String actual = props.getProperty("foo");
        Assert.assertNull(actual);
    }

    @Test
    public void encryptedValuesWithDefaultSuffix() {
        SecureProperties props = new SecureProperties(algorithm);
        props.setEncryptedProperty("foo", "bar"); // bar value is stored encrypted
        String actual = props.getProperty("foo"); // if property is encrypted, it gets automatically decrypted
        // actual == "bar"
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void encryptedValuesWorkWithCustomSuffix() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setEncryptedProperty("foo", "bar");
        String actual = props.getProperty("foo");
        Assert.assertNotNull("Value under foo must not be null", actual);
        Assert.assertEquals("bar", actual);
    }

    @Test
    public void valueIsEncryptedInside() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setEncryptedProperty("foo", "bar");
        String encryptedValue = props.getOriginalProperty("foo");
        Assert.assertTrue(encryptedValue.endsWith("--mySuffix"));
        String encryptedValueNoSuffix = encryptedValue.substring(0, encryptedValue.length() - "--mySuffix".length());
        Assert.assertEquals(64, encryptedValueNoSuffix.length()); // 32 bytes of data
    }

    @Test
    public void valuesAreEncryptedWhenStored() throws IOException {
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

    @Test
    public void validateWithNonExistentValues() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        Assert.assertTrue(props.validateValue("foo", null));
        Assert.assertFalse(props.validateValue("foo", ""));
    }

    @Test
    public void validateWithNonNullValues() {
        SecureProperties props = new SecureProperties(algorithm, "--mySuffix");
        props.setProperty("foo", "bar");
        Assert.assertTrue(props.validateValue("foo", "bar"));
        Assert.assertFalse(props.validateValue("foo", "barr"));
    }
}
