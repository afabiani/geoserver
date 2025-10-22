/* (c) 2025 Open Source Geospatial Foundation - all rights reserved
 * GPL 2.0 at the root application directory.
 */
package org.geoserver.security.keycloak;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Collectors;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.AuthenticationCachingFilter;
import org.geoserver.security.filter.GeoServerAuthenticationFilter;
import org.geoserver.security.filter.GeoServerCompositeFilter;
import org.geoserver.security.filter.GeoServerLogoutFilter;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.RoleCalculator;
import org.geotools.util.logging.Logging;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Spring Security 6 Keycloak integration for GeoServer. - Bearer auth via Resource Server (JWT) - Interactive login via
 * oauth2Login (delegated to nested Spring filters) - RP-initiated logout against Keycloak end_session_endpoint
 *
 * <p>Drop-in replacement for the legacy Keycloak adapter filter.
 */
public class GeoServerKeycloakOAuth2Filter extends GeoServerCompositeFilter
        implements GeoServerAuthenticationFilter, LogoutHandler, AuthenticationCachingFilter {

    private static final java.util.logging.Logger LOG = Logging.getLogger(GeoServerKeycloakOAuth2Filter.class);

    /** When present as "true", redirect to /oauth2/authorization/{registrationId} */
    private static final String KEYCLOAK_LOGIN_BTN = "j_spring_keycloak_login";

    /** Registration id used by Spring oauth2Login (e.g., "keycloak"). */
    private String registrationId = "keycloak";

    /** Client ID for extracting roles from resource_access[clientId].roles */
    private String clientId;

    /** If true, no redirect challenges for anonymous requests; just 401 for missing/invalid bearer. */
    private boolean bearerOnly = false;

    /** If true, allow redirect entry point via GS attribute (compat with old behavior). */
    private boolean enableRedirectEntryPoint = true;

    /** Used for RP-initiated logout (id_token_hint + post_logout_redirect_uri). */
    private LogoutSuccessHandler logoutSuccessHandler;

    /** Resolve end_session_endpoint & client settings; also used to set logout handler per request. */
    private ClientRegistrationRepository clientRegistrationRepository;

    /** JWT decoder for bearer tokens (issuer / JWK set). */
    private JwtDecoder jwtDecoder;

    /** Map external roles to Spring authorities (no prefix). */
    private GrantedAuthoritiesMapper authoritiesMapper;

    /** Filter name from config, for auth cache keyspace. */
    private String filterName;

    public GeoServerKeycloakOAuth2Filter() {
        super();
        SimpleAuthorityMapper m = new SimpleAuthorityMapper();
        m.setPrefix(""); // keep names as-is
        m.setConvertToUpperCase(false);
        this.authoritiesMapper = m;
    }

    // -------------------- GeoServer SPI --------------------

    @Override
    public boolean applicableForHtml() {
        return true;
    }

    @Override
    public boolean applicableForServices() {
        return true;
    }

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig raw) throws IOException {
        super.initializeFromConfig(raw);
        if (!(raw instanceof GeoServerKeycloakOAuth2FilterConfig cfg)) {
            throw new IOException("Unsupported config type: " + raw.getClass().getName());
        }

        this.filterName = cfg.getName();
        this.setClientId(cfg.getClientId());
        this.setBearerOnly(cfg.isBearerOnly());
        this.setEnableRedirectEntryPoint(cfg.isEnableRedirectEntryPoint());

        String issuer = Objects.requireNonNull(cfg.getIssuerUri(), "issuerUri must not be null");
        String regId =
                (cfg.getRegistrationId() == null || cfg.getRegistrationId().isBlank())
                        ? "keycloak"
                        : cfg.getRegistrationId();
        this.setRegistrationId(regId);

        ClientRegistration reg =
                org.springframework.security.oauth2.client.registration.ClientRegistrations.fromIssuerLocation(issuer)
                        .registrationId(regId)
                        .clientId(cfg.getClientId())
                        .clientSecret(Optional.ofNullable(cfg.getClientSecret()).orElse(""))
                        .build();

        this.setClientRegistrationRepository(new InMemoryClientRegistrationRepository(reg));
        this.setJwtDecoder(org.springframework.security.oauth2.jwt.JwtDecoders.fromIssuerLocation(issuer));

        OidcClientInitiatedLogoutSuccessHandler logout =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        this.setLogoutSuccessHandler(logout);
    }

    // -------------------- Caching --------------------

    /** Cache based on Authorization header only (same semantics as legacy filter). */
    @Override
    public String getCacheKey(HttpServletRequest request) {
        String v = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (v != null && !v.isEmpty()) {
            if (LOG.isLoggable(Level.FINEST)) LOG.fine("cache key = " + v);
            return v;
        }
        return null;
    }

    // -------------------- Core filtering --------------------

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest raw = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // Reverse-proxy fix (x-forwarded-proto)
        HttpServletRequest request = wrapForForwardedProto(raw);

        // Try cache
        String cacheKey = authenticateFromCache(this, request);

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            // 1) Bearer first (service calls)
            boolean attemptedBearer = false;
            String authz = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authz != null && authz.startsWith("Bearer ")) {
                attemptedBearer = true;
                tryBearer(request, response);
            }

            // If bearer-only and still unauthenticated, stop after sending error
            if (attemptedBearer
                    && bearerOnly
                    && SecurityContextHolder.getContext().getAuthentication() == null) {
                return;
            }

            // 2) Interactive login kick-off when asked (back-compat button) or when entry point is enabled
            if (!attemptedBearer && (loginButtonPressed(request) || enableRedirectEntryPoint)) {
                // Let nested Spring OAuth2 filters do their thing (they’ll 302 to Keycloak)
                // Nothing to do here; just proceed.
            }

            // 3) Cache the post-authentication result (if any) — Option B (header-based caching)
            Authentication post = SecurityContextHolder.getContext().getAuthentication();
            if (post != null
                    && post.isAuthenticated()
                    && cacheKey != null
                    && authz != null
                    && authz.startsWith("Bearer ")
                    && filterName != null
                    && getSecurityManager() != null
                    && getSecurityManager().getAuthenticationCache() != null) {
                getSecurityManager().getAuthenticationCache().put(filterName, cacheKey, post);
            }
        }

        // Delegate to nested filters (oauth2Login chain etc.)
        super.doFilter(request, response, chain);
    }

    private boolean loginButtonPressed(HttpServletRequest request) {
        return "true".equals(request.getParameter(KEYCLOAK_LOGIN_BTN));
    }

    private HttpServletRequest wrapForForwardedProto(HttpServletRequest request) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public StringBuffer getRequestURL() {
                String url = super.getRequestURL().toString();
                String proto = super.getHeader("x-forwarded-proto");
                if (proto != null && url.startsWith("http://") && "https".equalsIgnoreCase(proto)) {
                    url = url.replaceFirst("^http", "https");
                }
                return new StringBuffer(url);
            }
        };
    }

    // -------------------- Bearer/JWT auth --------------------

    private void tryBearer(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (jwtDecoder == null) {
            if (bearerOnly) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
            return;
        }
        try {
            String tokenValue = extractBearer(request.getHeader(HttpHeaders.AUTHORIZATION));
            Jwt jwt = jwtDecoder.decode(tokenValue);

            // Basic time sanity (Nimbus handles most validation)
            if (jwt.getExpiresAt() != null && jwt.getExpiresAt().isBefore(Instant.now())) {
                throw new JwtException("JWT expired");
            }

            // Build authorities from Keycloak claims
            Set<String> roleNames = extractKeycloakRoles(jwt, clientId);
            Collection<? extends GrantedAuthority> mapped = authoritiesMapper.mapAuthorities(roleNames.stream()
                    .map(org.springframework.security.core.authority.SimpleGrantedAuthority::new)
                    .collect(Collectors.toList()));

            // Username from preferred_username (fallback sub)
            String username = Optional.ofNullable(jwt.getClaimAsString("preferred_username"))
                    .orElse(jwt.getSubject());

            // Build GeoServer roles & token
            Collection<GeoServerRole> gsRoles = toGeoServerRoles(mapped);
            if (!gsRoles.contains(GeoServerRole.AUTHENTICATED_ROLE)) {
                gsRoles.add(GeoServerRole.AUTHENTICATED_ROLE);
            }

            Object principal = GeoServerUser.ROOT_USERNAME.equals(username)
                    ? GeoServerUser.ROOT_USERNAME
                    : new User(username, "N/A", mapped);

            PreAuthenticatedAuthenticationToken auth = GeoServerUser.ROOT_USERNAME.equals(username)
                    ? new PreAuthenticatedAuthenticationToken(principal, null, Set.of(GeoServerRole.ADMIN_ROLE))
                    : new PreAuthenticatedAuthenticationToken(principal, null, gsRoles);

            // carry JWT as details (parity with old 'details' behavior)
            auth.setDetails(jwt);
            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (JwtException e) {
            LOG.log(Level.FINE, "JWT authentication failed", e);
            if (bearerOnly) {
                // 401 for API calls (same outcome as legacy when bearerOnly)
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
    }

    private static String extractBearer(String header) {
        return header.substring("Bearer ".length()).trim();
    }

    private static Set<String> extractKeycloakRoles(Jwt jwt, String clientId) {
        Set<String> roles = new LinkedHashSet<>();

        // realm_access.roles
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null) {
            Object r = realmAccess.get("roles");
            if (r instanceof Collection<?> c) {
                c.forEach(v -> roles.add(String.valueOf(v)));
            }
        }

        // resource_access[clientId].roles
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null && clientId != null) {
            Object client = resourceAccess.get(clientId);
            if (client instanceof Map<?, ?> m) {
                Object rr = m.get("roles");
                if (rr instanceof Collection<?> c) {
                    c.forEach(v -> roles.add(String.valueOf(v)));
                }
            }
        }
        return roles;
    }

    private Collection<GeoServerRole> toGeoServerRoles(Collection<? extends GrantedAuthority> src) {
        Collection<GeoServerRole> roles = new ArrayList<>();
        GeoServerRoleService roleService = getSecurityManager().getActiveRoleService();

        for (GrantedAuthority ga : src) {
            try {
                GeoServerRole r = roleService.getRoleByName(ga.getAuthority());
                roles.add(r != null ? r : new GeoServerRole(ga.getAuthority()));
            } catch (IOException e) {
                LOG.log(Level.WARNING, "Unable to resolve GeoServer role", e);
                roles.add(new GeoServerRole(ga.getAuthority()));
            }
        }

        try {
            RoleCalculator calc = new RoleCalculator(roleService);
            calc.addInheritedRoles(roles);
            calc.addMappedSystemRoles(roles);
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Role inheritance/mapping failed", e);
        }

        return roles;
    }

    // -------------------- Logout (RP-initiated) --------------------

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (logoutSuccessHandler == null) return;

        // GeoServer wants to redirect back to Referer (no query)
        String referer = request.getHeader(HttpHeaders.REFERER);
        String refererNoParams = referer != null ? referer.split("\\?")[0] : request.getContextPath() + "/web";

        // If handler is OIDC logout, set dynamic post-logout redirect URI
        if (logoutSuccessHandler instanceof OidcClientInitiatedLogoutSuccessHandler oidc) {
            try {
                oidc.setPostLogoutRedirectUri(refererNoParams);
            } catch (Exception ignore) {
                // tolerate cases where provider ignores it
            }
        }

        try {
            logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Logout from Keycloak failed.", e);
        }

        // Also set GS redirect attribute (parity with legacy)
        request.setAttribute(GeoServerLogoutFilter.LOGOUT_REDIRECT_ATTR, refererNoParams);
    }

    // -------------------- Setters (wired via XML) --------------------

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setBearerOnly(boolean bearerOnly) {
        this.bearerOnly = bearerOnly;
    }

    public void setEnableRedirectEntryPoint(boolean enable) {
        this.enableRedirectEntryPoint = enable;
    }

    public void setLogoutSuccessHandler(LogoutSuccessHandler handler) {
        this.logoutSuccessHandler = handler;
    }

    public LogoutSuccessHandler getLogoutSuccessHandler() {
        return logoutSuccessHandler;
    }

    public void setClientRegistrationRepository(ClientRegistrationRepository repo) {
        this.clientRegistrationRepository = repo;
    }

    public void setJwtDecoder(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper mapper) {
        this.authoritiesMapper = mapper;
    }
}
