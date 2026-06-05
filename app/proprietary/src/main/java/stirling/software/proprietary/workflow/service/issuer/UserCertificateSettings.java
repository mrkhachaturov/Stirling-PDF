package stirling.software.proprietary.workflow.service.issuer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.Getter;

/**
 * Application-owned configuration for per-user signing certificate issuance.
 *
 * <p>Mirrors the {@code system.serverCertificate.*} convention (plain {@code @Value} binding, so
 * {@code SYSTEM_USERCERTIFICATE_*} environment overrides apply). With the default {@code issuer:
 * selfsigned} none of the step-ca fields are read, so the feature is inert and adds no outbound
 * dependency when disabled.
 */
@Component
@Getter
public class UserCertificateSettings {

    /**
     * Whether the per-user certificate is offered as a managed ("Auto") signing identity in the
     * signing tools, independent of how it is issued ({@link #issuer}). When {@code false} the
     * per-user option is not advertised; enrolment at login still depends on {@link #issuer}.
     */
    @Value("${system.userCertificate.enabled:false}")
    private boolean enabled;

    /** Selected issuer: {@code selfsigned} (default) or {@code stepca}. */
    @Value("${system.userCertificate.issuer:selfsigned}")
    private String issuer;

    /**
     * step-ca base URL, e.g. {@code https://step-ca.internal:9000}. Required when issuer=stepca.
     */
    @Value("${system.userCertificate.caUrl:}")
    private String caUrl;

    /** step-ca OIDC provisioner name. Informational; used in diagnostics. */
    @Value("${system.userCertificate.provisioner:}")
    private String provisioner;

    /** RSA key size for generated user signing keys. */
    @Value("${system.userCertificate.keySize:2048}")
    private int keySize;

    /**
     * Optional path to a PEM bundle trusted when calling step-ca over TLS. Blank uses the default
     * JVM trust store.
     */
    @Value("${system.userCertificate.caBundlePath:}")
    private String caBundlePath;

    /** Connection + read timeout (seconds) for calls to step-ca. */
    @Value("${system.userCertificate.requestTimeoutSeconds:15}")
    private int requestTimeoutSeconds;

    /**
     * Group required to be enrolled a signing certificate. Blank disables the application-side
     * check (issuance authorization then rests solely with the CA). When set, only users whose OIDC
     * token carries this group in {@link #requiredGroupClaim} are enrolled at login; everyone else
     * (e.g. read-only office users) is skipped. Authentication is not authorization to sign.
     */
    @Value("${system.userCertificate.requiredGroup:}")
    private String requiredGroup;

    /** Name of the OIDC token claim listing the user's groups. */
    @Value("${system.userCertificate.requiredGroupClaim:groups}")
    private String requiredGroupClaim;

    public boolean isStepCaIssuer() {
        return StepCaUserCertificateIssuer.NAME.equalsIgnoreCase(normalizedIssuer());
    }

    public String normalizedIssuer() {
        return issuer == null || issuer.isBlank()
                ? SelfSignedUserCertificateIssuer.NAME
                : issuer.trim();
    }
}
