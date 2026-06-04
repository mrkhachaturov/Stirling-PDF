package stirling.software.proprietary.workflow.service.issuer;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Result of a {@link UserCertificateIssuer} issuance: the freshly generated private key and the
 * certificate chain to store alongside it.
 *
 * <p>For a self-signed issuer the chain is a single leaf certificate. For an external CA the chain
 * is leaf-first and includes any intermediates so the embedded PDF signature can build a path to
 * the trust anchor.
 */
public record IssuedUserCertificate(PrivateKey privateKey, X509Certificate[] chain) {

    public IssuedUserCertificate {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("chain must contain at least the leaf certificate");
        }
    }

    /** The end-entity (signing) certificate. */
    public X509Certificate leaf() {
        return chain[0];
    }
}
