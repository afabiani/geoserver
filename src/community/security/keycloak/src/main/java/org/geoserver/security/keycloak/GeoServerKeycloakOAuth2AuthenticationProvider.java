package org.geoserver.security.keycloak;

import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.AbstractFilterProvider;
import org.geoserver.security.filter.GeoServerSecurityFilter;
import org.geoserver.security.validation.SecurityConfigValidator;

public class GeoServerKeycloakOAuth2AuthenticationProvider extends AbstractFilterProvider {

    @Override
    public void configure(XStreamPersister xp) {
        super.configure(xp);
        var xs = xp.getXStream();
        xs.allowTypes(new Class[] {GeoServerKeycloakOAuth2FilterConfig.class});
        xs.alias("keycloakOAuth2", GeoServerKeycloakOAuth2FilterConfig.class);
    }

    @Override
    public Class<? extends GeoServerSecurityFilter> getFilterClass() {
        return GeoServerKeycloakOAuth2Filter.class;
    }

    @Override
    public GeoServerSecurityFilter createFilter(SecurityNamedServiceConfig cfg) {
        return new GeoServerKeycloakOAuth2Filter();
    }

    @Override
    public SecurityConfigValidator createConfigurationValidator(GeoServerSecurityManager sm) {
        return new GeoServerKeycloakOAuth2FilterConfigValidator(sm);
    }
}
