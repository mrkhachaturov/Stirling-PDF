package stirling.software.proprietary.workflow.service.issuer;

/**
 * Pluggable source of a per-user signing certificate.
 *
 * <p>An issuer owns only the "how is the key pair + certificate produced" decision. Persistence,
 * keystore packaging, password handling and the actual PDF signing remain owned by {@code
 * UserServerCertificateService} and are identical regardless of which issuer is selected.
 *
 * <p>The default implementation reproduces Stirling's historical behaviour (a self-signed
 * certificate). Alternative implementations may enrol the certificate from an external CA.
 */
public interface UserCertificateIssuer {

    /**
     * Configuration key that selects this issuer via {@code system.userCertificate.issuer}. Matched
     * case-insensitively.
     */
    String name();

    /** Produce a signing key pair and its certificate chain for the requested user. */
    IssuedUserCertificate issue(UserCertificateIssuanceRequest request) throws Exception;
}
