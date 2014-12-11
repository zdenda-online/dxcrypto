package cz.d1x.dxcrypto.props;

import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.SaltingAdapter;

import java.util.Objects;
import java.util.Properties;

/**
 * Extension of {@link java.util.Properties} that allows storing and reading encrypted values by given encryption
 * algorithm.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class SecureProperties extends Properties {

    private static final String DEFAULT_ENCRYPTED_PREFIX = "b3e856";

    private final EncryptionAlgorithm encryptionAlgorithm;
    private final String encryptedPropertyPrefix;

    /**
     * Creates a new properties that will use given encryption algorithm.
     * Default {@link #DEFAULT_ENCRYPTED_PREFIX} prefix will be used for recognition whether value is encrypted or not.
     *
     * @param encryptionAlgorithm algorithm used for encryption
     */
    public SecureProperties(EncryptionAlgorithm encryptionAlgorithm) {
        this(encryptionAlgorithm, DEFAULT_ENCRYPTED_PREFIX);
    }

    /**
     * Creates a new properties that will use given encryption algorithm.
     * Default {@link #DEFAULT_ENCRYPTED_PREFIX} prefix will be used for recognition whether value is encrypted or not.
     *
     * @param defaults            initial values for properties
     * @param encryptionAlgorithm algorithm used for encryption
     */
    public SecureProperties(Properties defaults, EncryptionAlgorithm encryptionAlgorithm) {
        this(defaults, encryptionAlgorithm, DEFAULT_ENCRYPTED_PREFIX);
    }

    /**
     * Creates a new properties that will use given encryption algorithm and given prefix will be used for recognition
     * whether value is encrypted or not.
     *
     * @param encryptionAlgorithm     algorithm used for encryption
     * @param encryptedPropertyPrefix prefix used for recognition of encrypted values (will be trimmed)
     */
    public SecureProperties(EncryptionAlgorithm encryptionAlgorithm, String encryptedPropertyPrefix) {
        this(null, encryptionAlgorithm, encryptedPropertyPrefix);
    }

    /**
     * Creates a new properties that will use given encryption algorithm and given prefix will be used for recognition
     * whether value is encrypted or not.
     *
     * @param defaults                initial values for properties
     * @param encryptionAlgorithm     algorithm used for encryption
     * @param encryptedPropertyPrefix prefix used for recognition of encrypted values (will be trimmed)
     * @throws IllegalArgumentException possible exception if given prefix is null or 0-length
     */
    public SecureProperties(Properties defaults, EncryptionAlgorithm encryptionAlgorithm, String encryptedPropertyPrefix) {
        super(defaults);
        this.encryptionAlgorithm = encryptionAlgorithm;
        if (encryptedPropertyPrefix == null || encryptedPropertyPrefix.trim().isEmpty()) {
            throw new IllegalArgumentException("Encryption prefix must be non-null and must have at least one character after trimming");
        }
        this.encryptedPropertyPrefix = encryptedPropertyPrefix.trim();
    }

    /**
     * Have the same functionality as {@link #setProperty(String, String)} but the value gets encrypted before it gets
     * stored within properties. The value gets automatically decrypted when {@link #getProperty(String)} or
     * {@link #getProperty(String, String)} is called.
     */
    public synchronized Object setEncryptedProperty(String key, String value) {
        String encryptedValue = encryptedPropertyPrefix + encryptionAlgorithm.encrypt(value);
        return super.setProperty(key, encryptedValue);
    }

    /**
     * {@inheritDoc}
     * <p/>
     * If the property starts with given (specified in constructor or default) prefix, it gets decrypted by defined
     * encryption algorithm. Note that {@link EncryptionException} can be thrown if encrypted property cannot be
     * decrypted by given algorithm.
     */
    @Override
    public String getProperty(String key) {
        return getEncrypted(super.getProperty(key));
    }

    /**
     * {@inheritDoc}
     * <p/>
     * If the property starts with given (specified in constructor or default) prefix, it gets decrypted by defined
     * encryption algorithm. Note that {@link EncryptionException} can be thrown if encrypted property cannot be
     * decrypted by given algorithm.
     */
    @Override
    public String getProperty(String key, String defaultValue) {
        return getEncrypted(super.getProperty(key, defaultValue));
    }

    /**
     * Validates whether given expected value is equal to the value in the properties under given key.
     *
     * @param key           key of property
     * @param expectedValue expected value of property
     * @return true if value of expected and the one in properties are equal, otherwise false.
     */
    public boolean validateValue(String key, String expectedValue) {
        String propertyValue = getProperty(key);
        return (propertyValue != null) ? propertyValue.equals(expectedValue) : (expectedValue == null);
    }

    private String getEncrypted(String value) {
        if (value != null && value.startsWith(encryptedPropertyPrefix)) {
            String withoutPrefix = value.substring(encryptedPropertyPrefix.length());
            return encryptionAlgorithm.decrypt(withoutPrefix);
        } else {
            return value;
        }
    }
}
