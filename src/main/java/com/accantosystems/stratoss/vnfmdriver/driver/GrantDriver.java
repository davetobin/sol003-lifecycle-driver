package com.accantosystems.stratoss.vnfmdriver.driver;

import static com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverConstants.*;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import com.accantosystems.stratoss.common.utils.LoggingUtils;
import com.accantosystems.stratoss.vnfmdriver.model.MessageDirection;
import com.accantosystems.stratoss.vnfmdriver.model.MessageType;
import com.accantosystems.stratoss.vnfmdriver.utils.RequestResponseLogUtils;

import lombok.RequiredArgsConstructor;

import org.etsi.sol003.granting.Grant;
import org.etsi.sol003.granting.GrantRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverProperties;
import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverProperties.Authentication;
import com.accantosystems.stratoss.vnfmdriver.model.AuthenticationType;
import com.accantosystems.stratoss.vnfmdriver.model.GrantCreationResponse;
import com.accantosystems.stratoss.vnfmdriver.service.GrantRejectedException;
import com.accantosystems.stratoss.vnfmdriver.service.OAuthClientCredentialsRestTemplateInterceptor;
import com.accantosystems.stratoss.vnfmdriver.utils.DynamicSslCertificateHttpRequestFactory;

/**
 * Driver implementing the ETSI SOL003 Grant interface
 */
//@Configuration
//@RequiredArgsConstructor
@Service("GrantDriver")
@ConditionalOnProperty(name = "vnfmdriver.grant.automatic", havingValue = "false")
public class GrantDriver {

    private final static Logger logger = LoggerFactory.getLogger(GrantDriver.class);

    private final static String API_CONTEXT_ROOT = "/grant/v1";
    private final static String API_PATH_GRANTS = "/grants";
    private final static String LOCATION_HEADER_PATH = API_CONTEXT_ROOT + API_PATH_GRANTS + "/";

    private final VNFMDriverProperties vnfmDriverProperties;
    private final RestTemplate authenticatedRestTemplate;

    public GrantDriver(VNFMDriverProperties vnfmDriverProperties, RestTemplateBuilder restTemplateBuilder, GrantResponseErrorHandler grantResponseErrorHandler) {
        this.vnfmDriverProperties = vnfmDriverProperties;
        this.authenticatedRestTemplate = getAuthenticatedRestTemplate(vnfmDriverProperties, restTemplateBuilder, grantResponseErrorHandler);
    }

    /**
     * Requests a grant for a particular VNF lifecycle operation.
     *
     * <ul>
     * <li>Sends GrantRequest message via HTTP POST to /grants</li>
     * <li>If grant provider supports the synchronous path, should receive 201 Created response with a {@link Grant} resource as the response body</li>
     * <li>If grant provider supports the asynchronous path, should receive 202 Accepted response with no response body and Location header to poll for grant response</li>
     * </ul>
     * 
     * @param grantRequest
     *            the request for permission from the NFVO to perform a particular VNF lifecycle operation.
     * @return the creation response, wrapping the grant resource if it exists and the grant location
     * @throws GrantRejectedException
     *             if the grant request was rejected
     * @throws GrantProviderException
     *             if there was an error communicating with the Grant Provider or it gave an unexpected response.
     */
    public GrantCreationResponse requestGrant(GrantRequest grantRequest) throws GrantRejectedException, GrantProviderException {

        final String url = vnfmDriverProperties.getGrant().getProvider().getUrl() + API_CONTEXT_ROOT + API_PATH_GRANTS;
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        final HttpEntity<GrantRequest> requestEntity = new HttpEntity<>(grantRequest, headers);
        final ResponseEntity<Grant> responseEntity;
        final String driverRequestId;
        UUID uuid = UUID.randomUUID();
        if(grantRequest != null){
            driverRequestId = grantRequest.getVnfLcmOpOccId();
            LoggingUtils.logEnabledMDC(grantRequest.toString(), MessageType.REQUEST, MessageDirection.SENT, uuid.toString(), MediaType.APPLICATION_JSON.toString(), "http",
                    RequestResponseLogUtils.getRequestSentProtocolMetaData(url, HttpMethod.POST.name(), headers), driverRequestId);
            try {
                responseEntity = authenticatedRestTemplate.exchange(url, HttpMethod.POST, requestEntity, Grant.class);
            } catch (SOL003ResponseException e) {
                LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                        RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), driverRequestId);
                throw new GrantProviderException(String.format("Unable to communicate with Grant Provider on [%s] which gave status %s", url, e.getProblemDetails().getStatus()), e);
            } catch (Exception e) {
                LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                        RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), driverRequestId);
                throw new GrantProviderException(String.format("Unable to communicate with Grant Provider on [%s]", url), e);
            } catch (Throwable e){
                // To log all unknown errors while making external call
                LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                        RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), driverRequestId);
                throw e;
            }
            LoggingUtils.logEnabledMDC(responseEntity.getBody() != null ? responseEntity.getBody().toString() : "", MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), responseEntity.getBody() != null?MediaType.APPLICATION_JSON_VALUE:"" , "http",
                    RequestResponseLogUtils.getResponseReceivedProtocolMetaData(responseEntity.getStatusCode().value(), LoggingUtils.getReasonPhrase(responseEntity.getStatusCode().value()), null), driverRequestId);
            if (HttpStatus.CREATED.equals(responseEntity.getStatusCode())) {
                // synchronous response - should find grant resource in body
                if (responseEntity.getBody() == null) {
                    throw new GrantProviderException("No response body");
                }
                return new GrantCreationResponse(responseEntity.getBody());
            } else if (HttpStatus.ACCEPTED.equals(responseEntity.getStatusCode())) {
                // asynchronous response - need to poll for grant resource, no body expected
                if (responseEntity.getBody() != null) {
                    throw new GrantProviderException("No response body expected");
                }
                String grantId = getGrantIdFromLocationHeader(responseEntity);
                return new GrantCreationResponse(grantId);
            } else {
                throw new GrantProviderException(String.format("Invalid status code [%s] received", responseEntity.getStatusCode()));
            }
        }else {
            // not making external call here so no need to have log entries in this case.
            throw new GrantProviderException("GrantRequest object is null");
        }
    }

    /**
     * Reads a grant for a particular VNF lifecycle operation.
     *
     * <ul>
     * <li>Sends HTTP GET request to /grants/grantId</li>
     * <li>If grant has been accepted, should receive 200 OK response with a {@link Grant} resource as the response body</li>
     * <li>If grant decision is still pending, should receive 202 Accepted response with no response body</li>
     * </ul>
     * 
     * @param grantId
     *            id of the grant resource on which a decision is pending
     * @return the grant resource if a grant decision has been made, null if still pending
     * @throws GrantRejectedException
     *             if the grant request was rejected
     * @throws GrantProviderException
     *             if there was an error communicating with the Grant Provider or it gave an unexpected response.
     */
    public Grant getGrant(String grantId) throws GrantRejectedException, GrantProviderException {
        final String url = vnfmDriverProperties.getGrant().getProvider().getUrl() + API_CONTEXT_ROOT + API_PATH_GRANTS + "/{grantId}";

        final HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        final HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
        final ResponseEntity<Grant> responseEntity;
        UUID uuid = UUID.randomUUID();
        // can't have the driverRequestId as yet, might not need in response log as well as we are already logging in the controller with Grant object
        LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(grantId), MessageType.REQUEST, MessageDirection.SENT, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                RequestResponseLogUtils.getRequestSentProtocolMetaData(url, HttpMethod.GET.name(), headers), null);
        try {
            responseEntity = authenticatedRestTemplate.exchange(url, HttpMethod.GET, requestEntity, Grant.class, grantId);
        } catch (SOL003ResponseException e) {
            LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                    RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), null);
            throw new GrantProviderException(String.format("Unable to communicate with Grant Provider on [%s] which gave status %s", url, e.getProblemDetails().getStatus()), e);
        } catch (Exception e) {
            LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                    RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), null);
            throw new GrantProviderException(String.format("Unable to communicate with Grant Provider on [%s]", url), e);
        } catch (Throwable e){
            // To log all unknown errors while making external call
            LoggingUtils.logEnabledMDC(RequestResponseLogUtils.convertToJson(e.getMessage()), MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), MediaType.APPLICATION_JSON_VALUE, "http",
                    RequestResponseLogUtils.getResponseReceivedProtocolMetaData(HttpStatus.INTERNAL_SERVER_ERROR.value(), LoggingUtils.getReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value()), null), null);
            throw e;
        }
        LoggingUtils.logEnabledMDC(responseEntity.getBody() != null ? responseEntity.getBody().toString() : "", MessageType.RESPONSE, MessageDirection.RECEIVED, uuid.toString(), responseEntity.getBody() != null?MediaType.APPLICATION_JSON_VALUE:"", "http",
                RequestResponseLogUtils.getResponseReceivedProtocolMetaData(responseEntity.getStatusCode().value(), LoggingUtils.getReasonPhrase(responseEntity.getStatusCode().value()), responseEntity.getHeaders()), null);
        if (HttpStatus.OK.equals(responseEntity.getStatusCode())) {
            // grant was accepted and grant resource is available and should be found in body
            if (responseEntity.getBody() == null) {
                throw new GrantProviderException("No response body");
            }
            return responseEntity.getBody();
        } else if (HttpStatus.ACCEPTED.equals(responseEntity.getStatusCode())) {
            // grant not yet accepted nor rejected - should continue to poll until grant resource available
            if (responseEntity.getBody() != null) {
                throw new GrantProviderException("No response body expected");
            }
            return null;
        } else {
            throw new GrantProviderException(String.format("Invalid status code [%s] received", responseEntity.getStatusCode()));
        }
    }

    protected RestTemplate getAuthenticatedRestTemplate() {
        return authenticatedRestTemplate;
    }

    private RestTemplate getAuthenticatedRestTemplate(VNFMDriverProperties vnfmDriverProperties, RestTemplateBuilder restTemplateBuilder, GrantResponseErrorHandler grantResponseErrorHandler) {
        RestTemplateBuilder customRestTemplateBuilder = configureRestTemplateBuilder(restTemplateBuilder, grantResponseErrorHandler);

        Authentication authenticationProperties = vnfmDriverProperties.getGrant().getProvider().getAuthentication();
        final String authenticationTypeString = authenticationProperties.getType();
        final AuthenticationType authenticationType = AuthenticationType.valueOfIgnoreCase(authenticationTypeString);
        if (authenticationType == null) {
            throw new IllegalArgumentException(String.format("Invalid authentication type specified for Grant Provider [%s]", authenticationTypeString));
        }

        RestTemplate authenticatedRestTemplate;
        switch (authenticationType) {
        case BASIC:
            String username = checkProperty(authenticationProperties.getUsername(), AUTHENTICATION_USERNAME);
            String password = checkProperty(authenticationProperties.getPassword(), AUTHENTICATION_PASSWORD);

            authenticatedRestTemplate = getBasicAuthenticatedRestTemplate(customRestTemplateBuilder, username, password);
            break;
        case OAUTH2:
            String accessTokenUri = checkProperty(authenticationProperties.getAccessTokenUri(), AUTHENTICATION_ACCESS_TOKEN_URI);
            String clientId = checkProperty(authenticationProperties.getClientId(), AUTHENTICATION_CLIENT_ID);
            String clientSecret = checkProperty(authenticationProperties.getClientSecret(), AUTHENTICATION_CLIENT_SECRET);

            authenticatedRestTemplate = getOAuth2AuthenticatedRestTemplate(customRestTemplateBuilder, authenticationProperties, accessTokenUri, clientId, clientSecret);

            break;
        case COOKIE:
            throw new UnsupportedOperationException("Attempting to use Cookie-based authentication which is unsupported for the grant provider.");
        default:
            authenticatedRestTemplate = getUnauthenticatedRestTemplate(customRestTemplateBuilder);
        }
        return authenticatedRestTemplate;
    }

    private RestTemplate getUnauthenticatedRestTemplate(RestTemplateBuilder customRestTemplateBuilder) {
        logger.info("Configuring unauthenticated RestTemplate.");
        return customRestTemplateBuilder.build();
    }

    private RestTemplate getBasicAuthenticatedRestTemplate(RestTemplateBuilder customRestTemplateBuilder, String username, String password) {
        logger.info("Configuring Basic Authentication RestTemplate.");
        return customRestTemplateBuilder.basicAuthentication(username, password)
                .build();
    }

    private RestTemplate getOAuth2AuthenticatedRestTemplate(RestTemplateBuilder customRestTemplateBuilder, Authentication authenticationProperties, String accessTokenUri, String clientId, String clientSecret) {
        ClientRegistration.Builder clientRegistrationBuilder = ClientRegistration.withRegistrationId(clientId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS )
                .tokenUri(accessTokenUri);

        if (StringUtils.hasText(authenticationProperties.getScope())) {
                    clientRegistrationBuilder.scope(Arrays.asList(authenticationProperties.getScope().split(",")));
                }  
        ClientRegistration clientRegistration = clientRegistrationBuilder.build();
        return customRestTemplateBuilder
                .additionalInterceptors(new OAuthClientCredentialsRestTemplateInterceptor(authorizedClientManager(clientRegistration), clientRegistration))
                .build();

        }

    private OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistration clientRegistration) {
        var authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();

        ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepository(clientRegistration);
        OAuth2AuthorizedClientService oAuth2AuthorizedClientService = authorizedClientService(clientRegistrationRepository);
        var authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
        }

    private OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {

        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
        }

        public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
            return new InMemoryClientRegistrationRepository(clientRegistration);
        }

    private RestTemplateBuilder configureRestTemplateBuilder(RestTemplateBuilder restTemplateBuilder, GrantResponseErrorHandler grantResponseErrorHandler) {
        RestTemplateBuilder customRestTemplateBuilder = restTemplateBuilder.errorHandler(grantResponseErrorHandler)
                .requestFactory(DynamicSslCertificateHttpRequestFactory.class)
                .setConnectTimeout(vnfmDriverProperties.getRestConnectTimeout())
                .setReadTimeout(vnfmDriverProperties.getRestReadTimeout());
        logger.info("Initialising RestTemplate configuration");
        return customRestTemplateBuilder;
    }

    private String getGrantIdFromLocationHeader(ResponseEntity<Grant> responseEntity) throws GrantProviderException {
        URI location = responseEntity.getHeaders().getLocation();
        if (location == null) {
            throw new GrantProviderException("Expected to find Location header in Grant Provider response");
        }
        String locationStr = location.toString();
        // would expect the location to look like this '/grant/v1/grants/{grantId}'
        int grantIdIndex = locationStr.lastIndexOf(LOCATION_HEADER_PATH) + LOCATION_HEADER_PATH.length();
        if (grantIdIndex < LOCATION_HEADER_PATH.length() || grantIdIndex >= locationStr.length()) {
            throw new GrantProviderException(String.format("Unable to extract grantId from Location header [%s]", locationStr));
        }
        return locationStr.substring(grantIdIndex);
    }

    private String checkProperty(String property, String propertyName) {
        if (StringUtils.isEmpty(property)) {
            throw new IllegalArgumentException(String.format("Must specify a property value for [%s]", propertyName));
        }
        return property;
    }
}
