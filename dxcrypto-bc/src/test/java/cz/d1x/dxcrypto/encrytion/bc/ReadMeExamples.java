package cz.d1x.dxcrypto.encrytion.bc;

import cz.d1x.dxcrypto.encryption.EncryptionAlgorithm;
import cz.d1x.dxcrypto.encryption.EncryptionAlgorithms;
import cz.d1x.dxcrypto.encryption.bc.BouncyCastleFactories;
import cz.d1x.dxcrypto.encryption.crypto.CryptoFactories;
import org.junit.Test;

/**
 * Tests README examples.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class ReadMeExamples {

    @Test
    public void bc() {
        // switching to all encryption algorithms to bouncy castle
        BouncyCastleFactories bcFactories = new BouncyCastleFactories();
        EncryptionAlgorithms.defaultFactories(bcFactories);

        // now build algorithms the same way as before
        EncryptionAlgorithm bcAes = EncryptionAlgorithms.aes("secretPassphrase")
                .build();

        // using bouncy castle only for one specific algorithm
        EncryptionAlgorithms.defaultFactories(new CryptoFactories()); // back to default
        EncryptionAlgorithms.aes256("secretPassphrase")
                .keyFactory(bcFactories.derivedKeyFactory()) // optional, default will work as well
                .engineFactory(bcFactories.aes256()) // be sure to use correct factory
                .build();
    }
}
