package stirling.software.proprietary.workflow.service.issuer;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Decides whether an authenticated user is authorized to be enrolled a signing certificate.
 *
 * <p>Authentication is not authorization: a user who signs in (e.g. to read documents) is not
 * thereby allowed to sign. When a required group is configured, only users whose OIDC token lists
 * that group are eligible. The check is <em>fail-closed</em> — a missing claim or absent group
 * means not eligible — and is an optimization in front of the CA's own authoritative group
 * restriction.
 */
final class UserCertificateGroupPolicy {

    private UserCertificateGroupPolicy() {}

    static boolean isEligible(String requiredGroup, String claimName, Map<String, Object> claims) {
        if (requiredGroup == null || requiredGroup.isBlank()) {
            return true; // no application-side gate; rely on the CA
        }
        if (claimName == null || claimName.isBlank() || claims == null) {
            return false;
        }
        return groupValues(claims.get(claimName)).stream()
                .anyMatch(group -> group.equalsIgnoreCase(requiredGroup.trim()));
    }

    private static List<String> groupValues(Object rawClaim) {
        if (rawClaim == null) {
            return List.of();
        }
        if (rawClaim instanceof Collection<?> collection) {
            return collection.stream()
                    .filter(java.util.Objects::nonNull)
                    .map(String::valueOf)
                    .toList();
        }
        return List.of(String.valueOf(rawClaim));
    }
}
