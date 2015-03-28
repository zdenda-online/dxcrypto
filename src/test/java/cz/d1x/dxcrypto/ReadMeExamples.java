package cz.d1x.dxcrypto;

import cz.d1x.dxcrypto.common.CombineAlgorithm;
import cz.d1x.dxcrypto.common.ConcatAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithms;
import cz.d1x.dxcrypto.encryption.RSAKeysGenerator;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingAlgorithms;
import cz.d1x.dxcrypto.hash.SaltedHashingAlgorithm;
import cz.d1x.dxcrypto.props.SecureProperties;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;

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
    public void test() {
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

        CombineAlgorithm combineAlg = new ConcatAlgorithm(); // your implementation
        SaltedHashingAlgorithm customSaltedSha256 = HashingAlgorithms.sha256()
                .salted(combineAlg)
                .build();

        // AES
        EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secretPassphrase")
                .keySalt("saltForKeyDerivation") // optional
                .keyHashIterations(4096) // optional
                        // .combineSplitAlgorithm(...) // optional, how to combine/split IV and cipherText
                        // .bytesRepresentation(...) // optional, defaults to lower-cased HEX
                .build();

        byte[] asBytes2 = aes.encrypt(new byte[]{'h', 'e', 'l', 'l', 'o'});
        byte[] andBack2 = aes.decrypt(asBytes2);

        // DES
        EncryptionAlgorithm des = EncryptionAlgorithms.tripleDes("secret")
                .build(); // default key salt, iterations count and combine/split alg.

        String asString3 = des.encrypt("hello");
        String andBack3 = des.decrypt(asString3);

        // custom key
        BigInteger modulus = BigInteger.ZERO; // your modulus (n)
        BigInteger publicExponent = BigInteger.ZERO; // your public exponent (e)
        BigInteger privateExponent = BigInteger.ZERO; // your private exponent (d)
//        EncryptionAlgorithm customRsa = EncryptionAlgorithms.rsa()
//                .publicKey(modulus, publicExponent)
//                .privateKey(modulus, privateExponent)
//                .build();

        // generated keys
        RSAKeysGenerator keysGen = new RSAKeysGenerator();
        KeyPair keys = keysGen.generateKeys();
        EncryptionAlgorithm genRsa = EncryptionAlgorithms.rsa()
                .keyPair(keys)
                .build();

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
