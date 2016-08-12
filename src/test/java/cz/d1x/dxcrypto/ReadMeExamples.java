package cz.d1x.dxcrypto;

import cz.d1x.dxcrypto.common.Combining;
import cz.d1x.dxcrypto.common.ConcatAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithms;
import cz.d1x.dxcrypto.encryption.RSAKeysGenerator;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingAlgorithms;
import cz.d1x.dxcrypto.hash.SaltedHashingAlgorithm;
import cz.d1x.dxcrypto.props.SecureProperties;
import org.junit.Test;

/**
 * Tests README examples.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class ReadMeExamples {

    /**
     * Copy paste README examples in here and verify
     */
    @Test
    public void hashing() {
        HashingAlgorithm sha256 = HashingAlgorithms.sha256()
                .encoding("UTF-8") // optional, defaults to UTF-8
                // .bytesRepresentation(...) // optional, defaults to lower-cased HEX
                .build();

        byte[] asBytes = sha256.hash(new byte[]{'h', 'e', 'l', 'l', 'o'});
        String asString = sha256.hash("hello"); // 2cf24dba5fb0a...


        HashingAlgorithm repeatedSha512 = HashingAlgorithms.sha512()
                .repeated(27)
                .build();
        String repeated = repeatedSha512.hash("hello"); // hash(hash("hello")) ~ 27x

        SaltedHashingAlgorithm saltedSha256 = HashingAlgorithms.sha256()
                .salted()
                .build();
        String salted = saltedSha256.hash("your input text", "your salt");

        Combining combining = new ConcatAlgorithm(); // your implementation
        SaltedHashingAlgorithm customSaltedSha256 = HashingAlgorithms.sha256()
                .salted(combining)
                .build();
    }

    @Test
    public void symmetricEncryption() {
        // AES
        EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secretPassphrase")
                .keySalt("saltForKeyDerivation") // optional
                .keyHashIterations(4096) // optional
                // .ivAndOutputCombining(...) // optional, how to combine/split IV and cipherText
                // .bytesRepresentation(...) // optional, defaults to lower-cased HEX
                .build();

        byte[] asBytes2 = aes.encrypt(new byte[]{'h', 'e', 'l', 'l', 'o'});
        byte[] andBack2 = aes.decrypt(asBytes2);

        // DES
        EncryptionAlgorithm des = EncryptionAlgorithms.tripleDes("secret")
                .build(); // default key salt, iterations count and combine/split alg.

        String asString3 = des.encrypt("hello");
        String andBack3 = des.decrypt(asString3);
    }

    @Test
    public void asymmetricEncryption() {
        // Commented because test would fail with these big integer values.
        // custom key
//        BigInteger modulus = BigInteger.ONE; // your modulus (n)
//        BigInteger publicExponent = BigInteger.ONE; // your public exponent (e)
//        BigInteger privateExponent = BigInteger.ONE; // your private exponent (d)
//        EncryptionAlgorithm customRsa = EncryptionAlgorithms.rsa()
//                .publicKey(modulus, publicExponent)
//                .privateKey(modulus, privateExponent)
//                .build();

        // generated keys
        RSAKeysGenerator keysGen = new RSAKeysGenerator();
        RSAKeysGenerator.RSAKeys keys = keysGen.generateKeys();
        EncryptionAlgorithm genRsa = EncryptionAlgorithms.rsa()
                .publicKey(keys.getModulus(), keys.getPublicExponent())
                .privateKey(keys.getModulus(), keys.getPrivateExponent())
                .build();
    }

    @Test
    public void customEngines() {
        // Commented because test would fail with nulls.
        // Custom factory for one specific algorithm
//        SymmetricEncryptionEngineFactory customFactory = null; // your implementation
//        EncryptionAlgorithm customAes = EncryptionAlgorithms.aes("secretPassphrase")
//                .engineFactory(customFactory)
//                .build();

        // Custom set of factories (for all supported algorithms of EncryptionAlgorithms)
//        EncryptionFactories factories = null; // your implementation
//        EncryptionAlgorithms.defaultFactories(factories);
//        EncryptionAlgorithm customAes256 = EncryptionAlgorithms.aes256("secretPassphrase")
//                // no need to set engineFactory as in previous example
//                .build();
    }

    @Test
    public void secureProperties() {
        EncryptionAlgorithm algorithm = EncryptionAlgorithms.aes("whatever").build(); // your algorithm
        SecureProperties props = new SecureProperties(algorithm);
        props.setProperty("plainProperty", "imGoodBoy");
        props.setEncryptedProperty("encryptedProperty", "myDirtySecret");

//        props.store(...);
        // plainProperty=imGoodBoy
        // encryptedProperty=bf165faf5067...

        // automatic decryption of values
        String decrypted = props.getProperty("encryptedProperty"); // "myDirtySecret"
        String original = props.getOriginalProperty("encryptedProperty"); // bf165...
    }
}
