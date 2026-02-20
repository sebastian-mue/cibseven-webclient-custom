package org.cibseven.webapp.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.cibseven.webapp.auth.exception.AuthenticationException;
import org.cibseven.webapp.auth.providers.JwtUserProvider;
import org.cibseven.webapp.auth.rest.StandardLogin;
import org.cibseven.webapp.exception.SystemException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Custom user provider for Goetel SPOT integration.
 * 
 * This is a custom implementation that replaces the standard CIB seven authentication
 * mechanism to integrate with the existing Goetel SPOT backend authentication system.
 * 
 * Background - Why this custom provider is needed:
 * 
 * The Goetel SPOT application has modified the standard Camunda REST API path from
 * /engine-rest to /rest (configured via cibseven.webclient.engineRest.path=/rest).
 * 
 * SPOT implements a CamundaAuthenticationFilter that intercepts ALL requests to /rest/*
 * and enforces authentication. This filter validates requests using stateful JWT tokens
 * that the SPOT application tracks server-side.
 * 
 * Impact:
 * - The standard CIB seven authentication doesn't support SPOT's JWT token system
 * 
 * How this provider solves the problem:
 * 1. User enters credentials in the webclient login page
 * 2. This provider sends Basic Auth request to SPOT backend /rest/authentication/login
 * 3. SPOT backend validates credentials and returns a stateful JWT token
 * 4. The JWT token is stored in SpotUser.backendJwtToken field
 * 5. The webclient creates its own session token (authToken) for the frontend
 * 6. All REST calls to SPOT backend include the stored JWT token via getEngineRestToken()
 * 7. SPOT's CamundaAuthenticationFilter validates the JWT and allows the request
 * 
 * CURRENT LIMITATION - Token Expiration:
 * 
 * The SPOT JWT token expires after a configured time (default: 60 minutes).
 * 
 * When the token expires:
 * - All API calls to SPOT backend will fail with 401 Unauthorized
 * - The CIB seven WebClient will display a generic error popup to the user
 * - The user MUST manually re-login to continue working
 * 
 * 
 * FUTURE IMPROVEMENT - Automatic Token Refresh:
 * 
 * Configuration in application.yaml:
 * cibseven.webclient.user.provider: org.cibseven.webapp.auth.SpotUserProvider
 * cibseven.webclient.engineRest.url: <SPOT backend URL>
 * cibseven.webclient.engineRest.path: /rest  (SPOT's custom path instead of /engine-rest)
 * 
 * Related custom modifications:
 * - SpotUser.backendJwtToken field (stores the SPOT JWT token)
 * - EngineService.getProcessEngineNames() (returns static engine name to avoid auth issues on login page)
 */
public class SpotUserProvider extends BaseUserProvider<StandardLogin> {
	
	private static final Logger log = LoggerFactory.getLogger(SpotUserProvider.class);
	
	@Value("${cibseven.webclient.authentication.jwtSecret:}") 
	private String secret;
	
	@Value("${cibseven.webclient.engineRest.url:http://localhost:8080}") 
	private String backendUrl;

	@Value("${cibseven.webclient.authentication.validMinutes:60}")
	private int validMinutes;

	@Value("${cibseven.webclient.authentication.prolongMinutes:30}")
	private int prolongMinutes;
	
	private static String SPOT_AUTHENTICATION_URL = "/rest/authentication/";
	private static String SPOT_LOGIN_PATH = "login";
	private static String SPOT_LOGOUT_PATH = "logout";
	@Autowired
	private RestTemplate restTemplate;
	
	private ObjectMapper objectMapper = new ObjectMapper();
	
	@PostConstruct
	public void init() {
		log.info("Initializing SpotUserProvider with backendUrl: {}", backendUrl);
		settings = new JwtTokenSettings(secret, validMinutes, prolongMinutes);
		checkKey();
		
		log.info("SpotUserProvider initialized successfully");
	}
	
	@Override
	public User login(StandardLogin login, HttpServletRequest rq) {	
		log.info("Login attempt for user: {}", login.getUsername());
		log.debug("Backend URL: {}", backendUrl);
		
		try {
			// Create Basic Auth credentials for SPOT backend authentication
			String credentials = login.getUsername() + ":" + login.getPassword();
			String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
			
			HttpHeaders headers = new HttpHeaders();
			headers.set("Authorization", "Basic " + encodedCredentials);
			HttpEntity<String> entity = new HttpEntity<>(headers);
			
			// Call SPOT backend authentication endpoint
			String authUrl = backendUrl + SPOT_AUTHENTICATION_URL + SPOT_LOGIN_PATH;
			log.info("Calling backend authentication endpoint: {}", authUrl);
			
			ResponseEntity<String> response = restTemplate.exchange(authUrl, HttpMethod.POST, entity, String.class);
			log.info("Backend authentication response status: {}", response.getStatusCode());
			
			JsonNode authResponse = objectMapper.readTree(response.getBody());
			log.debug("Backend authentication response body received");

			// Create webclient user object
			SpotUser user = new SpotUser(login.getUsername());
			setEngineFromRequest(user, rq);
			
			user.setUserID(authResponse.get("userName").asText());
			user.setDisplayName(authResponse.get("userName").asText());
			
			// CRITICAL: Store the SPOT backend JWT token for all subsequent API calls
			// This token must be included in all REST requests to the SPOT backend
			String backendJwt = authResponse.get("jwt").asText();
			user.setBackendJwtToken(backendJwt);
			log.info("Backend JWT token stored for user: {}", user.getUserID());
			
			// Create webclient session token for frontend authentication
			user.setAuthToken(createToken(getSettings(), true, false, user));
			log.info("Webclient auth token created for user: {}", user.getUserID());
			
			return user;
		} catch (HttpClientErrorException e) {
			log.error("Backend authentication failed for user {}: HTTP {} - {}", 
				login.getUsername(), e.getStatusCode(), e.getResponseBodyAsString());
			throw new AuthenticationException(login.getUsername());
		} catch (Exception e) {
			log.error("Unexpected error during login for user {}: {}", login.getUsername(), e.getMessage(), e);
			throw new AuthenticationException(login.getUsername());	
		}
	}
	
	@Override
	public void logout(User user) {
		log.info("Logout request for user: {}", user != null ? user.getId() : "null");
		
		if (user instanceof SpotUser) {
			SpotUser spotUser = (SpotUser) user;
			String backendJwtToken = spotUser.getBackendJwtToken();
			
			if (backendJwtToken != null && !backendJwtToken.isEmpty()) {
				try {
					HttpHeaders headers = new HttpHeaders();
					headers.set("Authorization", "Bearer " + backendJwtToken);
					HttpEntity<String> entity = new HttpEntity<>(headers);
					
					String logoutUrl = backendUrl + SPOT_AUTHENTICATION_URL + SPOT_LOGOUT_PATH;
					log.info("Calling backend logout endpoint: {}", logoutUrl);
					
					restTemplate.exchange(logoutUrl, HttpMethod.POST, entity, String.class);
					log.info("Backend logout successful for user: {}", user.getId());
				} catch (Exception e) {
					log.warn("Backend logout failed for user {}: {}", user.getId(), e.getMessage());
				}
			} else {
				log.warn("No backend JWT token found for user: {}", user.getId());
			}
		}
	}

	@Override
	public User getUserInfo(User user, String userId) {
		log.debug("getUserInfo called for userId: {} by user: {}", userId, user != null ? user.getId() : "null");
		
		if (user.getId().equals(userId)) {
			return user;
		} else {
			log.warn("User {} attempted to get info for different user: {}", user.getId(), userId);
			throw new AuthenticationException(userId);
		}
	}

	@Override
	public User getSelfInfoJSessionId(String userId, String jSessionId, HttpServletRequest rq) {
		log.debug("getSelfInfoJSessionId called for userId: {}", userId);
		return null;
	}
	
	@Override	
	public User deserialize(String json, String token) {
		log.debug("Deserializing user from JSON");
		try {
			SpotUser user = objectMapper.readValue(json, SpotUser.class);
			user.setAuthToken(token);
			log.debug("User deserialized: {}", user.getId());
			return user;
		} catch (IOException x) {
			log.error("Failed to deserialize user: {}", x.getMessage(), x);
			throw new SystemException(x);
		}
	}

	@Override
	public String serialize(User user) {
		log.debug("Serializing user: {}", user != null ? user.getId() : "null");
		try {
			return objectMapper.writeValueAsString(user);
		} catch (JsonProcessingException x) {
			log.error("Failed to serialize user: {}", x.getMessage(), x);
			throw new SystemException(x);
		}
	}

	@Override 
	public User verify(Claims userClaims) {
		log.debug("Verifying user claims");
		return deserialize(userClaims.get("user").toString(), null);
	}
	
	@Override
	public StandardLogin createLoginParams() {
		return new StandardLogin();
	}
	
	/**
	 * Returns the authentication token for REST API calls to the SPOT backend.
	 * 
	 * This method is called by the REST client infrastructure whenever making calls
	 * to the Camunda/SPOT backend engine. It provides the JWT token that was obtained
	 * during login and stored in SpotUser.backendJwtToken.
	 * 
	 * The token is returned in Bearer format: "Bearer <jwt-token>"
	 * 
	 * This is a critical part of the authentication flow - without this token,
	 * all REST API calls to the SPOT backend would fail with 401 Unauthorized.
	 * 
	 * @param user The authenticated CIBUser containing the backend JWT token
	 * @return The Bearer token string for Authorization header, or empty string if not available
	 */
	@Override
	public String getEngineRestToken(CIBUser user) {
		if (user instanceof SpotUser) {
			SpotUser spotUser = (SpotUser) user;
			if (spotUser.getBackendJwtToken() != null) {
				String token = "Bearer " + spotUser.getBackendJwtToken();
				log.debug("Returning engine REST token for user: {}", spotUser.getId());
				return token;
			}
		}
		log.warn("No backend JWT token available for user: {}", user != null ? user.getId() : "null");
		return "";
	}
}
