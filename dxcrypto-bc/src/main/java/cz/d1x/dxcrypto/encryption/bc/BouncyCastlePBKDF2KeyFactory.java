package cz.d1x.dxcrypto.encryption.bc;

import cz.d1x.dxcrypto.common.ByteArray;
import cz.d1x.dxcrypto.encryption.EncryptionException;
import cz.d1x.dxcrypto.encryption.key.DerivedKeyParams;
import cz.d1x.dxcrypto.encryption.key.EncryptionKeyFactory;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Key factory that uses implementation of PBKDF2 function from Bouncy Castle for key derivation.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public class BouncyCastlePBKDF2KeyFactory implements EncryptionKeyFactory<ByteArray, DerivedKeyParams> {

    @Override
    public ByteArray newKey(DerivedKeyParams keyParams) throws EncryptionException {
        PBEParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA1Digest());
        gen.init(keyParams.getPassword(), keyParams.getSalt(), keyParams.getIterations());
        KeyParameter keyParam = (KeyParameter) gen.generateDerivedParameters(keyParams.getKeySize());
        return new ByteArray(keyParam.getKey());
    }
}