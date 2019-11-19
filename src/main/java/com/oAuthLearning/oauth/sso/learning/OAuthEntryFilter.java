package com.oAuthLearning.oauth.sso.learning;

import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;

public class OAuthEntryFilter extends OAuth2ClientAuthenticationProcessingFilter {
    public OAuthEntryFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }
}
