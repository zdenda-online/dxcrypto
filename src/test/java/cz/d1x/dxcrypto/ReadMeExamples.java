package cz.d1x.dxcrypto;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.common.Combining;
import cz.d1x.dxcrypto.common.ConcatAlgorithm;
import cz.d1x.dxcrypto.common.HexRepresentation;
import cz.d1x.dxcrypto.encryption.*;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParameters;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import cz.d1x.dxcrypto.hash.HashingAlgorithm;
import cz.d1x.dxcrypto.hash.HashingAlgorithms;
import cz.d1x.dxcrypto.hash.SaltedHashingAlgorithm;
import cz.d1x.dxcrypto.props.SecureProperties;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Test;

import java.math.BigInteger;

/**
 * Tests README examples.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class ReadMeExamples {

    /**
     * Copy paste README examples in here and verify
     */
    public void hashing() {
        HashingAlgorithm sha256 = HashingAlgorithms.sha256()
                .build();

        // byte[] or String based methods
        byte[] hashedBytes = sha256.hash(new byte[]{'h', 'e', 'l', 'l', 'o'});
        String hashedString = sha256.hash("hello"); // 2cf24dba5fb0a...

        // customization of hashing function
        HashingAlgorithm customizedSha512 = HashingAlgorithms.sha512()
                .encoding("UTF-8") // optional, defaults to UTF-8
                .bytesRepresentation(new HexRepresentation(true)) // optional, defaults to lower-cased HEX
                .repeated(27) // optional, defaults to no repeating
                .build();

        // salting (with default combining of input text and salt)
        SaltedHashingAlgorithm saltedSha1 = HashingAlgorithms.sha1()
                .salted()
                .build();
        String salted = saltedSha1.hash("your input text", "your salt");

        // salting with custom combining of input text and salt
        Combining combining = new ConcatAlgorithm(); // you can implement your custom combining
        SaltedHashingAlgorithm customSaltedSha256 = HashingAlgorithms.sha256()
                .salted(combining)
                .build();
    }

    public void symmetricEncryption() {
        // AES with PBKDF2 key derivation from given password
        EncryptionAlgorithm aes = EncryptionAlgorithms.aes("secretPassword")
                .build();

        // byte[] or String based methods
        byte[] encryptedBytes = aes.encrypt(new byte[]{'h', 'e', 'l', 'l', 'o'});
        byte[] decryptedBytes = aes.decrypt(encryptedBytes);
        String encryptedString = aes.encrypt("hello");
        String decryptedString = aes.decrypt(encryptedString);

        // customization of symmetric encryption algorithm with PBKDF2
        EncryptionAlgorithm customizedAes = EncryptionAlgorithms.aes("secretPassphrase")
                .keySalt("saltForKeyDerivation") // optional, salt for key derivation
                .keyHashIterations(4096) // optional, hash iterations for key derivation
                .ivAndOutputCombining(new ConcatAlgorithm()) // optional, combining IV and output
                .bytesRepresentation(new HexRepresentation(true)) // optional, how to represent bytes
                .build();

        // custom AES key (without key derivation function)
        byte[] key = new byte[16]; // your key (somehow filled), must have correct size for algorithm!
        EncryptionAlgorithm customKeyAes = EncryptionAlgorithms.aes()
                .key(key)
                .build();
    }

    public void asymmetricEncryption() {
        BigInteger modulus = BigInteger.ONE; // your modulus (n)
        BigInteger publicExponent = BigInteger.ONE; // your public exponent (e)
        BigInteger privateExponent = BigInteger.ONE; // your private exponent (d)
        EncryptionAlgorithm rsa = EncryptionAlgorithms.rsa()
                .publicKey(modulus, publicExponent)
                .privateKey(modulus, privateExponent)
                .build();

        // generated keys
        RSAKeysGenerator keysGen = new RSAKeysGenerator();
        RSAKeysGenerator.RSAKeys keys = keysGen.generateKeys();
        EncryptionAlgorithm genRsa = EncryptionAlgorithms.rsa()
                .publicKey(keys.getModulus(), keys.getPublicExponent())
                .privateKey(keys.getModulus(), keys.getPrivateExponent())
                .build();
    }

    public void customEngines() {
        // Custom factory for one specific algorithm
        SymmetricEncryptionEngineFactory<ByteArray> customFactory = null; // your implementation
        EncryptionAlgorithm customAes = EncryptionAlgorithms.aes("secretPassphrase")
                .engineFactory(customFactory)
                .build();

        // Global configuration for all factories
        EncryptionFactories factories = null; // your implementation of all factories
        EncryptionAlgorithms.defaultFactories(factories);
        EncryptionAlgorithm customAes256 = EncryptionAlgorithms.aes256("secretPassphrase")
                // no need to set engineFactory as they are globally set now
                .build();
    }

    public void secureProperties() {
        EncryptionAlgorithm algorithm = EncryptionAlgorithms.aes("whatever").build(); // your algorithm
        SecureProperties props = new SecureProperties(algorithm);
        props.setProperty("plainProperty", "imGoodBoy");
        props.setEncryptedProperty("encryptedProperty", "myDirtySecret");

        // props.store(...);
        // plainProperty=imGoodBoy
        // encryptedProperty=bf165faf5067...

        // automatic decryption of values
        String decrypted = props.getProperty("encryptedProperty"); // "myDirtySecret"
        String original = props.getOriginalProperty("encryptedProperty"); // bf165...
    }

    @Test
    public void bouncyCastle() {
        EncryptionAlgorithm bcAes = EncryptionAlgorithms.aes256("secretPassphrase")
                .keyFactory(new BouncyCastlePBKDF2KeyFactory())
                .engineFactory(new BouncyCastleAESEngineFactory())
                .build();

        String encrypted = bcAes.encrypt("ahoj");
        String decrypted = bcAes.decrypt(encrypted);
        System.out.println(decrypted);
    }

    class BouncyCastlePBKDF2KeyFactory implements EncryptionKeyFactory<ByteArray, DerivedKeyParameters> {

        @Override
        public ByteArray newKey(DerivedKeyParameters keyParams) throws EncryptionException {
            PBEParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA1Digest());
            gen.init(keyParams.getPassword(), keyParams.getSalt(), keyParams.getIterations());
            KeyParameter keyParam = (KeyParameter) gen.generateDerivedParameters(keyParams.getKeySize());
            return new ByteArray(keyParam.getKey());
        }
    }

    class BouncyCastleAESEngineFactory implements SymmetricEncryptionEngineFactory<ByteArray> {

        @Override
        public EncryptionEngine newEngine(ByteArray key) {
            KeyParameter keyParam = new KeyParameter(key.getValue());
            return new BouncyCastleAESEngine(keyParam);
        }
    }

    class BouncyCastleAESEngine implements EncryptionEngine {

        private final KeyParameter keyParam;

        public BouncyCastleAESEngine(KeyParameter keyParam) {
            this.keyParam = keyParam;
        }

        @Override
        public byte[] encrypt(byte[] input, byte[] initVector) throws EncryptionException {
            return doOperation(input, initVector, true);
        }

        @Override
        public byte[] decrypt(byte[] input, byte[] initVector) throws EncryptionException {
            return doOperation(input, initVector, false);
        }

        private byte[] doOperation(byte[] input, byte[] initVector, boolean isEncrypt) {
            CipherParameters params = new ParametersWithIV(keyParam, initVector);
            BlockCipherPadding padding = new PKCS7Padding();
            BlockCipher engine = new CBCBlockCipher(new AESEngine());
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, padding);
            cipher.init(isEncrypt, params);

            byte[] output = new byte[cipher.getOutputSize(input.length)];
            int length = cipher.processBytes(input, 0, input.length, output, 0);
            try {
                length += cipher.doFinal(output, 0);
            } catch (InvalidCipherTextException e) {
                throw new EncryptionException("Encryption fails", e);
            }

            // Remove output padding
            byte[] out = new byte[length];
            System.arraycopy(output, 0, out, 0, length);
            return out;
        }
    }
}
