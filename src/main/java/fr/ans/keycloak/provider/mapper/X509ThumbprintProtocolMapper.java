/*
 * (c) Copyright 1998-2023, ANS. All rights reserved.
 */
package fr.ans.keycloak.provider.mapper;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

public class X509ThumbprintProtocolMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

	private static final Logger LOGGER = Logger.getLogger(X509ThumbprintProtocolMapper.class);

	public static final String PROVIDER_ID = "ANS-X509-protocol-mapper";

	private static final String NODE_NAME = "x5t#S256";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static {
		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, X509ThumbprintProtocolMapper.class);
	}

	@Override
	public String getDisplayCategory() {
		return "Token mapper";
	}

	@Override
	public String getDisplayType() {
		return "X509 thumbprint";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		return "Adds a Base64 encoded X509 thumbprint to the claim";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		X509Certificate[] certs = keycloakSession.getContext().getHttpRequest().getClientCertificateChain();
		if (certs == null || certs.length == 0) {
			// No x509 client cert
			LOGGER.warn("No x509 client certificate found.");
			return;
		}
		try {
			String base64Thumbprint = computeBase64SHA256Thumbprint(certs[0]);
			JsonNode claimValue = formatClaimValue(base64Thumbprint);
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
		} catch (CertificateEncodingException | NoSuchAlgorithmException | IOException e) {
			LOGGER.errorf("Error while calculating Base64SHA256Thumbprint:", e);
		}
	}

	public static String computeBase64SHA256Thumbprint(final X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		var md = MessageDigest.getInstance("SHA-256");
		md.update(cert.getEncoded());
		String thumbprint = DatatypeConverter.printHexBinary(md.digest()).toLowerCase();
		return java.util.Base64.getEncoder().encodeToString(thumbprint.getBytes());
	}

	public static JsonNode formatClaimValue(final String data) throws IOException {
		Map<String, Object> map = new HashMap<>();
		map.put(NODE_NAME, data);
		return JsonSerialization.createObjectNode(map);
	}
}
