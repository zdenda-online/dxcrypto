package cz.d1x.dxcrypto.encrytion.bc;


import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.EncryptionEngine;
import cz.d1x.dxcrypto.encryption.bc.BouncyCastleFactories;
import cz.d1x.dxcrypto.encryption.crypto.CryptoFactories;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParams;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class BCEncryptionAlgorithmsTest {

    private final CryptoFactories CRYPTO_FACTORIES = new CryptoFactories();
    private final BouncyCastleFactories BC_FACTORIES = new BouncyCastleFactories();
    private final Random RANDOM = new Random();

    @Test
    public void aesHaveSameOutputsAsCryptoForStringBasedPasswords() {
        byte[] keyPass = "s3ce3t-keyPass".getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[17];
        RANDOM.nextBytes(salt);
        int iterations = 27;
        DerivedKeyParams keyParams = new DerivedKeyParams(keyPass, salt, iterations, 128);

        ByteArray cryptoKey = CRYPTO_FACTORIES.derivedKeyFactory().newKey(keyParams);
        ByteArray bcKey = BC_FACTORIES.derivedKeyFactory().newKey(keyParams);

        Assert.assertArrayEquals(cryptoKey.getValue(), bcKey.getValue());

        EncryptionEngine cryptoEngine = CRYPTO_FACTORIES.aes().newEngine(cryptoKey);
        EncryptionEngine bcEngine = BC_FACTORIES.aes().newEngine(cryptoKey);

        byte[] input = new byte[RANDOM.nextInt(500)];
        RANDOM.nextBytes(input);
        byte[] iv = new byte[128 / 8];
        RANDOM.nextBytes(iv);

        byte[] cryptoOutput = cryptoEngine.encrypt(input, iv);
        byte[] bcOutput = bcEngine.encrypt(input, iv);

//        Assert.assertArrayEquals(cryptoOutput, bcOutput);

        byte[] cryptoBack = cryptoEngine.decrypt(cryptoOutput, iv);
        byte[] bcBack = bcEngine.decrypt(bcOutput, iv);

        Assert.assertArrayEquals(cryptoBack, input);
        Assert.assertArrayEquals(bcBack, input);
    }
}
