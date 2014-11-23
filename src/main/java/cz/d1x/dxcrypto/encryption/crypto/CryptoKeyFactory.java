package cz.d1x.dxcrypto.encryption.crypto;

import cz.d1x.dxcrypto.encryption.KeyFactory;

import java.security.Key;

/**
 * Base class for key factories that use {@link CryptoSymmetricAlgorithm}.
 *
 * @author Zdenek Obst, zdenek.obst-at-gmail.com
 */
public abstract class CryptoKeyFactory implements KeyFactory<Key> {
    // this only gives information that returned key is java.security.Key
}
