package stirling.software.proprietary.workflow.service.issuer;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/** Selects the active {@link UserCertificateIssuer} from {@code system.userCertificate.issuer}. */
@Component
@Slf4j
public class UserCertificateIssuerResolver {

    private final Map<String, UserCertificateIssuer> issuersByName;
    private final UserCertificateSettings settings;

    public UserCertificateIssuerResolver(
            List<UserCertificateIssuer> issuers, UserCertificateSettings settings) {
        this.settings = settings;
        Map<String, UserCertificateIssuer> map = new HashMap<>();
        for (UserCertificateIssuer issuer : issuers) {
            map.put(issuer.name().toLowerCase(Locale.ROOT), issuer);
        }
        this.issuersByName = map;
    }

    public UserCertificateIssuer resolve() {
        String requested = settings.normalizedIssuer().toLowerCase(Locale.ROOT);
        UserCertificateIssuer issuer = issuersByName.get(requested);
        if (issuer == null) {
            log.warn(
                    "Unknown user certificate issuer '{}'; falling back to self-signed", requested);
            return issuersByName.get(SelfSignedUserCertificateIssuer.NAME);
        }
        return issuer;
    }

    /** True when the configured issuer is not the default self-signed one. */
    public boolean isExternalIssuer() {
        return !SelfSignedUserCertificateIssuer.NAME.equalsIgnoreCase(settings.normalizedIssuer());
    }
}
