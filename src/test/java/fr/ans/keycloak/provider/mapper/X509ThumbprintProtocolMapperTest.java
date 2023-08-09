/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.provider.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.oidc.mappers.FullNameMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.mockito.Mockito;


final class X509ThumbprintProtocolMapperTest {

	private X509ThumbprintProtocolMapperTest() {}
	
	static final String CLAIM_NAME = "cnf";
	
    @Test
    public void shouldTokenMapperDisplayCategory() {
    	final String tokenMapperDisplayCategory = new FullNameMapper().getDisplayCategory();
        assertThat(new X509ThumbprintProtocolMapper().getDisplayCategory()).isEqualTo(tokenMapperDisplayCategory);
    }

    @Test
    public void shouldHaveDisplayType() {
        assertThat(new X509ThumbprintProtocolMapper().getDisplayType()).isNotBlank();
    }

    @Test
    public void shouldHaveHelpText() {
        assertThat(new X509ThumbprintProtocolMapper().getHelpText()).isNotBlank();
    }

    @Test
    public void shouldHaveIdId() {
        assertThat(new X509ThumbprintProtocolMapper().getId()).isNotBlank();
    }

    @Test
    public void shouldHaveProperties() {
        final List<String> configPropertyNames = new X509ThumbprintProtocolMapper().getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .collect(Collectors.toList());
        assertThat(configPropertyNames).containsExactly(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN);
    }

    @Test
    public void shouldAddClaim() throws Exception {
        final KeycloakSession session = givenKeycloakSession();

        final AccessToken accessToken = transformAccessToken(session);

        assertThat(accessToken.getOtherClaims().get(CLAIM_NAME)).isEqualTo(X509ThumbprintProtocolMapper.formatClaimValue("ODY0OWI0NDY1MGMwZjliODBjYWYyNDNlMGE1MTg2ODFkYTA0YzliMWQ0YmUzMDc3NjUwNGNmZGM1NzI4NjQxNQ=="));
    }

    private KeycloakSession givenKeycloakSession() {
    	KeycloakSession kcSession = Mockito.mock(KeycloakSession.class);
    	KeycloakContext kcContext = Mockito.mock(KeycloakContext.class);
        HttpRequest req = Mockito.mock(HttpRequest.class);
        
        when(kcSession.getContext()).thenReturn(kcContext);
        when(kcContext.getHttpRequest()).thenReturn(req);
        when(req.getClientCertificateChain()).thenReturn(getCertificates());
        
        return kcSession;
    }
    
    private X509Certificate[] getCertificates() {
    	
    	InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("psc.mtls.henix.asipsante.fr.pem");
    	X509Certificate cert = null;
    	try {
    		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate)certFactory.generateCertificate(is);
		} catch (CertificateException e) {

		}
    	
		return new X509Certificate[] {cert};
    }


    private AccessToken transformAccessToken(KeycloakSession kcSession) {
        final ProtocolMapperModel mappingModel = new ProtocolMapperModel();
        mappingModel.setConfig(createConfig());
        return new X509ThumbprintProtocolMapper().transformAccessToken(new AccessToken(), mappingModel, kcSession, null, null);
    }

    private Map<String, String> createConfig() {
        final Map<String, String> result = new HashMap<>();
        result.put("access.token.claim", "true");
        result.put("claim.name", CLAIM_NAME);
        return result;
    }
}
