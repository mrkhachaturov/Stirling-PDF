package stirling.software.proprietary.workflow.service.issuer;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import stirling.software.proprietary.security.model.User;
import stirling.software.proprietary.security.service.UserService;
import stirling.software.proprietary.workflow.service.UserServerCertificateService;

/**
 * Enrols a user's signing certificate at login when an external (OIDC-backed) issuer is configured.
 *
 * <p>Why login and not on first use: the per-user certificate is otherwise created lazily during
 * session finalization, which runs under the session owner's security context — the participant's
 * OIDC id token is not available there. Enrolling here, on the user's own successful login,
 * captures a fresh id token in the correct context so the certificate exists before it is ever
 * needed.
 *
 * <p>For the default self-signed issuer this listener does nothing; lazy generation is unaffected.
 * Enrollment is best-effort and never propagates failures into the login flow.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class UserCertificateOidcEnrollmentListener {

    private final UserCertificateIssuerResolver issuerResolver;
    private final UserCertificateSettings settings;
    private final UserService userService;
    private final UserServerCertificateService certificateService;

    @EventListener
    public void onAuthenticationSuccess(InteractiveAuthenticationSuccessEvent event) {
        if (!settings.isStepCaIssuer() || !issuerResolver.isExternalIssuer()) {
            return;
        }

        Authentication authentication = event.getAuthentication();
        if (authentication == null
                || !(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
            return;
        }
        if (oidcUser.getIdToken() == null) {
            return;
        }
        String idToken = oidcUser.getIdToken().getTokenValue();
        if (idToken == null || idToken.isBlank()) {
            return;
        }

        String username = oidcUser.getName();

        // Authentication is not authorization to sign: read-only users must not be provisioned a
        // signing certificate. Skip anyone outside the configured signing group. Read the group
        // from the ID token specifically — that is the same source step-ca's leaf template gates on
        // (.Token.*), since the ID token is what we forward as the one-time token.
        if (!UserCertificateGroupPolicy.isEligible(
                settings.getRequiredGroup(),
                settings.getRequiredGroupClaim(),
                oidcUser.getIdToken().getClaims())) {
            log.debug(
                    "User {} is not in the required signing group '{}'; skipping certificate"
                            + " enrolment",
                    username,
                    settings.getRequiredGroup());
            return;
        }

        try {
            User user = userService.findByUsernameIgnoreCase(username).orElse(null);
            if (user == null) {
                return;
            }
            if (certificateService.hasUserCertificate(user.getId())) {
                return;
            }
            certificateService.enrollUserCertificate(user, idToken);
            log.info("Enrolled step-ca signing certificate for user {} at login", username);
        } catch (Exception e) {
            // Never block login on enrolment failure; the certificate can be retried next login.
            log.warn(
                    "Failed to enrol step-ca signing certificate for user {} at login: {}",
                    username,
                    e.getMessage());
        }
    }
}
