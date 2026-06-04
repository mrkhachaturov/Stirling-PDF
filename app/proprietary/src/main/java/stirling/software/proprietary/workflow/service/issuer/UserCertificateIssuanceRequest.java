package stirling.software.proprietary.workflow.service.issuer;

import stirling.software.proprietary.security.model.User;

/**
 * Inputs for a certificate issuance.
 *
 * @param user the account the certificate identifies
 * @param oidcIdToken an OIDC id token asserting the user's identity, or {@code null}. Used by
 *     issuers that enrol from an OIDC-backed CA; ignored by the self-signed issuer. When {@code
 *     null} an OIDC issuer may fall back to the token of the currently authenticated request.
 */
public record UserCertificateIssuanceRequest(User user, String oidcIdToken) {

    public UserCertificateIssuanceRequest {
        if (user == null) {
            throw new IllegalArgumentException("user must not be null");
        }
    }

    /** Request without an explicitly supplied OIDC token. */
    public static UserCertificateIssuanceRequest forUser(User user) {
        return new UserCertificateIssuanceRequest(user, null);
    }
}
