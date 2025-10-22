/* (c) 2025 Open Source Geospatial Foundation - all rights reserved */
package org.geoserver.security.keycloak;

import java.io.Serial;
import java.util.Objects;
import org.geoserver.platform.GeoServerEnvironment;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.PreAuthenticatedUserNameFilterConfig;
import org.geoserver.security.config.SecurityAuthFilterConfig;
import org.geoserver.security.config.SecurityAuthProviderConfig;
import org.geoserver.security.config.SecurityConfig;

public class GeoServerKeycloakOAuth2FilterConfig extends PreAuthenticatedUserNameFilterConfig
        implements SecurityAuthFilterConfig, SecurityAuthProviderConfig, Cloneable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public final boolean equals(Object o) {
        if (!(o instanceof GeoServerKeycloakOAuth2FilterConfig that)) return false;

        return enableRedirectEntryPoint == that.enableRedirectEntryPoint
                && bearerOnly == that.bearerOnly
                && uppercaseAuthorities == that.uppercaseAuthorities
                && Objects.equals(id, that.id)
                && Objects.equals(name, that.name)
                && Objects.equals(className, that.className)
                && Objects.equals(userGroupServiceName, that.userGroupServiceName)
                && Objects.equals(issuerUri, that.issuerUri)
                && Objects.equals(jwkSetUri, that.jwkSetUri)
                && Objects.equals(clientId, that.clientId)
                && Objects.equals(clientSecret, that.clientSecret)
                && Objects.equals(registrationId, that.registrationId)
                && Objects.equals(redirectUriTemplate, that.redirectUriTemplate)
                && Objects.equals(scopes, that.scopes)
                && Objects.equals(postLogoutRedirectUri, that.postLogoutRedirectUri)
                && Objects.equals(authorityPrefix, that.authorityPrefix);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(id);
        result = 31 * result + Objects.hashCode(name);
        result = 31 * result + Objects.hashCode(className);
        result = 31 * result + Objects.hashCode(userGroupServiceName);
        result = 31 * result + Objects.hashCode(issuerUri);
        result = 31 * result + Objects.hashCode(jwkSetUri);
        result = 31 * result + Objects.hashCode(clientId);
        result = 31 * result + Objects.hashCode(clientSecret);
        result = 31 * result + Objects.hashCode(registrationId);
        result = 31 * result + Objects.hashCode(redirectUriTemplate);
        result = 31 * result + Objects.hashCode(scopes);
        result = 31 * result + Boolean.hashCode(enableRedirectEntryPoint);
        result = 31 * result + Boolean.hashCode(bearerOnly);
        result = 31 * result + Objects.hashCode(postLogoutRedirectUri);
        result = 31 * result + Boolean.hashCode(uppercaseAuthorities);
        result = 31 * result + Objects.hashCode(authorityPrefix);
        return result;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getClassName() {
        return className;
    }

    @Override
    public void setClassName(String className) {
        this.className = className;
    }

    @Override
    public String getUserGroupServiceName() {
        return userGroupServiceName;
    }

    @Override
    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getRedirectUriTemplate() {
        return redirectUriTemplate;
    }

    public void setRedirectUriTemplate(String redirectUriTemplate) {
        this.redirectUriTemplate = redirectUriTemplate;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public boolean isEnableRedirectEntryPoint() {
        return enableRedirectEntryPoint;
    }

    public void setEnableRedirectEntryPoint(boolean enableRedirectEntryPoint) {
        this.enableRedirectEntryPoint = enableRedirectEntryPoint;
    }

    public boolean isBearerOnly() {
        return bearerOnly;
    }

    public void setBearerOnly(boolean bearerOnly) {
        this.bearerOnly = bearerOnly;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }

    public boolean isUppercaseAuthorities() {
        return uppercaseAuthorities;
    }

    public void setUppercaseAuthorities(boolean uppercaseAuthorities) {
        this.uppercaseAuthorities = uppercaseAuthorities;
    }

    public String getAuthorityPrefix() {
        return authorityPrefix;
    }

    public void setAuthorityPrefix(String authorityPrefix) {
        this.authorityPrefix = authorityPrefix;
    }

    private String id;
    private String name;
    private String className;
    private String userGroupServiceName;

    // Spring/OIDC essentials
    private String issuerUri;
    private String jwkSetUri; // optional (issuer discovery if null)
    private String clientId;
    private String clientSecret;
    private String registrationId = "keycloak";
    private String redirectUriTemplate; // optional
    private String scopes = "openid profile email";

    // Behavior flags
    private boolean enableRedirectEntryPoint = true;
    private boolean bearerOnly = false;

    // Logout
    private String postLogoutRedirectUri; // optional

    // Authority mapping
    private boolean uppercaseAuthorities = false;
    private String authorityPrefix = ""; // keep empty for no prefix

    // getters/setters omitted for brevity ...

    @Override
    public boolean providesAuthenticationEntryPoint() {
        return true;
    }

    @Override
    public SecurityConfig clone(boolean allowEnvParametrization) {
        final GeoServerEnvironment env = GeoServerExtensions.bean(GeoServerEnvironment.class);
        GeoServerKeycloakOAuth2FilterConfig target;
        try {
            target = (GeoServerKeycloakOAuth2FilterConfig) this.clone();
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException(e);
        }
        if (target != null
                && allowEnvParametrization
                && env != null
                && GeoServerEnvironment.allowEnvParametrization()) {
            // common pattern: resolve name, issuerUri, etc. if you use ${...} placeholders
            target.setName((String) env.resolveValue(name));
            target.setIssuerUri((String) env.resolveValue(issuerUri));
            target.setClientId((String) env.resolveValue(clientId));
            target.setClientSecret((String) env.resolveValue(clientSecret));
        }
        return target;
    }

    @Override
    public void initBeforeSave() {
        // no-op
    }
}
