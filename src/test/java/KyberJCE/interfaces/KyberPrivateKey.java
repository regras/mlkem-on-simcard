package KyberJCE.interfaces;

import KyberJCE.provider.KyberKeySize;

/**
 *
 * @author Steven K Fisher <swiftcryptollc@gmail.com>
 */
public interface KyberPrivateKey extends KyberKey {

    static final long serialVersionUID = 47572612783495691L;

    /**
     * Returns the private value, <code>x</code>.
     *
     * @return the private value, <code>x</code>
     */
    public byte[] getX();

    public KyberKeySize getKyberKeySize();
}
