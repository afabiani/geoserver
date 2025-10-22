package org.geoserver.security.keycloak;

import static org.geoserver.security.validation.SecurityConfigException.CLASS_WRONG_TYPE_$2;

import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.validation.FilterConfigException;
import org.geoserver.security.validation.FilterConfigValidator;

public class GeoServerKeycloakOAuth2FilterConfigValidator extends FilterConfigValidator {

    public GeoServerKeycloakOAuth2FilterConfigValidator(GeoServerSecurityManager sm) {
        super(sm);
    }

    @Override
    public void validateFilterConfig(SecurityNamedServiceConfig raw) throws FilterConfigException {
        if (!(raw instanceof GeoServerKeycloakOAuth2FilterConfig cfg)) {
            throw new FilterConfigException(
                    CLASS_WRONG_TYPE_$2, raw.getClass().getName(), GeoServerKeycloakOAuth2FilterConfig.class.getName());
        }
        if (cfg.getIssuerUri() == null || cfg.getIssuerUri().isBlank()) {
            throw new FilterConfigException("issuerUri must be provided");
        }
        if (cfg.getClientId() == null || cfg.getClientId().isBlank()) {
            throw new FilterConfigException("clientId must be provided");
        }
        try {
            // early fail if issuer is wrong / JWKs not reachable in runtime classpath context
            org.springframework.security.oauth2.jwt.JwtDecoders.fromIssuerLocation(cfg.getIssuerUri());
        } catch (RuntimeException e) {
            throw new FilterConfigException(null, "OIDC discovery/JWKs validation failed: " + e.getMessage());
        }
    }
}
