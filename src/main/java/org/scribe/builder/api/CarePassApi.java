package org.scribe.builder.api;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.JsonTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

/**
 * CarePass OAuth2 
 *
 */
public class CarePassApi extends DefaultApi20 {
	private static final String AUTHORIZE_URL = "https://qaapi.aetna.com/carepass/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code";
	private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL
			+ "&scope=%s";

	@Override
	public String getAccessTokenEndpoint() {		
		return "https://qaapi.aetna.com/carepass/oauth/token?grant_type=authorization_code";
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		Preconditions.checkValidUrl(config.getCallback(),
				"Must provide a valid url as callback");
		// Append scope if present
		if (config.hasScope()) {
			return String.format(SCOPED_AUTHORIZE_URL, config.getApiKey(),
					 OAuthEncoder.encode(config.getCallback()),
					 OAuthEncoder.encode(config.getScope()));
		} else {
			return String.format(AUTHORIZE_URL, config.getApiKey(),
					 OAuthEncoder.encode(config.getCallback()));
		}
	}

	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new JsonTokenExtractor();
	}

}
