package stirling.software.common.service;

import java.security.KeyStore;

/**
 * Seam exposing the per-user signing certificate to the core layer (e.g. {@code
 * CertSignController}), mirroring {@link ServerCertificateServiceInterface}. The implementation
 * lives in the proprietary workflow module; core depends only on this interface and resolves the
 * acting user by username so no proprietary {@code User}/id type crosses the boundary.
 */
public interface UserCertificateServiceInterface {

    /** Whether the per-user certificate is offered as a managed ("Auto") signing identity. */
    boolean isEnabled();

    /**
     * Returns the user's signing keystore, auto-provisioning it via the configured issuer if
     * absent.
     *
     * @param username the acting (authenticated) user's username
     */
    KeyStore getOrCreateUserKeyStore(String username) throws Exception;

    /** Returns the password protecting the user's keystore. */
    String getUserKeystorePassword(String username) throws Exception;
}
