package com.accantosystems.stratoss.vnfmdriver.driver;

import static com.accantosystems.stratoss.vnfmdriver.test.TestConstants.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

import java.net.URI;

import org.etsi.sol003.granting.Grant;
import org.etsi.sol003.granting.GrantRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.client.RestClientTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.client.MockRestServiceServer;

import com.accantosystems.stratoss.vnfmdriver.model.GrantCreationResponse;

@RestClientTest({ GrantDriver.class, GrantResponseErrorHandler.class })
@AutoConfigureWireMock(port = 0)
@ActiveProfiles("test")
public class GrantDriverTest {

    private static final String BASE_API_ROOT = "/grant/v1";
    private static final String GRANT_ENDPOINT = BASE_API_ROOT + "/grants";

    @Autowired
    private GrantDriver grantDriver;

    @Test
    public void testRequestGrantSync() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withCreatedEntity(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                        .body(loadFileIntoString("examples/GrantResource.json"))
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();
        final GrantCreationResponse grantCreationResponse = grantDriver.requestGrant(grantRequest);

        assertThat(grantCreationResponse).isNotNull();
        assertThat(grantCreationResponse.getGrantId()).isNotNull();
        assertThat(grantCreationResponse.getGrantId()).isEqualTo(TEST_GRANT_ID);
        assertThat(grantCreationResponse.getGrant()).isNotNull();
        assertThat(grantCreationResponse.getGrant().getId()).isEqualTo(TEST_GRANT_ID);
    }

    @Test
    public void testRequestGrantAsync() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.ACCEPTED).location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID)));

        final GrantRequest grantRequest = new GrantRequest();
        final GrantCreationResponse grantCreationResponse = grantDriver.requestGrant(grantRequest);

        assertThat(grantCreationResponse).isNotNull();
        assertThat(grantCreationResponse.getGrantId()).isNotNull();
        assertThat(grantCreationResponse.getGrantId()).isEqualTo(TEST_GRANT_ID);
        assertThat(grantCreationResponse.getGrant()).isNull();
    }

    @Test
    public void testRequestGrantWithUnknownException() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withServerError());

        final GrantRequest grantRequest = new GrantRequest();
        GrantProviderException exception = catchThrowableOfType(() -> grantDriver.requestGrant(grantRequest), GrantProviderException.class);
        SOL003ResponseException cause = (SOL003ResponseException) exception.getCause();

        assertThat(exception.getMessage()).isEqualTo("Unable to communicate with Grant Provider on [http://localhost:8080/grant/v1/grants] which gave status 500");
        assertThat(cause.getProblemDetails()).isNotNull();
        assertThat(cause.getProblemDetails().getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(cause.getProblemDetails().getDetail()).isEqualTo("Internal Server Error");
    }

    @Test
    public void testRequestGrantWithUnknownExceptionAndBody() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withServerError().body(TEST_EXCEPTION_MESSAGE));

        final GrantRequest grantRequest = new GrantRequest();
        GrantProviderException exception = catchThrowableOfType(() -> grantDriver.requestGrant(grantRequest), GrantProviderException.class);
        SOL003ResponseException cause = (SOL003ResponseException) exception.getCause();

        assertThat(exception.getMessage()).isEqualTo("Unable to communicate with Grant Provider on [http://localhost:8080/grant/v1/grants] which gave status 500");
        assertThat(cause.getProblemDetails()).isNotNull();
        assertThat(cause.getProblemDetails().getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(cause.getProblemDetails().getDetail()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase() + ": " + TEST_EXCEPTION_MESSAGE);
    }

    @Test
    public void testRequestGrantWithInvalidSuccessCode() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withSuccess().body(loadFileIntoString("examples/GrantResource.json"))
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Invalid status code [200 OK] received");
    }

    @Test
    public void testRequestGrantWithInvalidResponseCode() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.MOVED_PERMANENTLY)
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID)));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Invalid status code [301 MOVED_PERMANENTLY] received");
    }

    @Test
    public void testRequestGrantWithEmptyResponseBodyForCreated() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withCreatedEntity(null)
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID)));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("No response body");
    }

    @Test
    public void testRequestGrantWithNonEmptyResponseBodyForAccepted() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.ACCEPTED).body(loadFileIntoString("examples/GrantResource.json"))
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("No response body expected");
    }

    @Test
    public void testRequestGrantWithMissingLocationForAccepted() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.ACCEPTED)
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Expected to find Location header in Grant Provider response");
    }

    @Test
    public void testRequestGrantWithMalformedLocationForAccepted() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.ACCEPTED)
                        .location(URI.create("malformed-location"))
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Unable to extract grantId from Location header [malformed-location]");
    }

    @Test
    public void testRequestGrantWithNoGrantIdInLocationForAccepted() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
                .andRespond(withStatus(HttpStatus.ACCEPTED)
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/"))
                        .contentType(MediaType.APPLICATION_JSON));

        final GrantRequest grantRequest = new GrantRequest();

        assertThatThrownBy(() -> grantDriver.requestGrant(grantRequest))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Unable to extract grantId from Location header [http://localhost:8080/grant/v1/grants/]");
    }

    @Test
    public void testGetGrantDecisionMade() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET)).andRespond(withSuccess()
                        .body(loadFileIntoString("examples/GrantResource.json"))
                        .contentType(MediaType.APPLICATION_JSON));

        final Grant grantResponse = grantDriver.getGrant(TEST_GRANT_ID);

        assertThat(grantResponse).isNotNull();
        assertThat(grantResponse.getId()).isNotNull();
        assertThat(grantResponse.getId()).isEqualTo(TEST_GRANT_ID);
    }

    @Test
    public void testGetGrantDecisionPending() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.ACCEPTED));

        final Grant grantResponse = grantDriver.getGrant(TEST_GRANT_ID);

        assertThat(grantResponse).isNull();
    }

    @Test
    public void testGetGrantWithUnknownException() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withServerError());

        GrantProviderException exception = catchThrowableOfType(() -> grantDriver.getGrant(TEST_GRANT_ID), GrantProviderException.class);
        SOL003ResponseException cause = (SOL003ResponseException) exception.getCause();

        assertThat(exception.getMessage()).isEqualTo("Unable to communicate with Grant Provider on [http://localhost:8080/grant/v1/grants/{grantId}] which gave status 500");
        assertThat(cause.getProblemDetails()).isNotNull();
        assertThat(cause.getProblemDetails().getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(cause.getProblemDetails().getDetail()).isEqualTo("Internal Server Error");
    }

    @Test
    public void testGetGrantWithUnknownExceptionAndBody() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withServerError().body(TEST_EXCEPTION_MESSAGE));

        GrantProviderException exception = catchThrowableOfType(() -> grantDriver.getGrant(TEST_GRANT_ID), GrantProviderException.class);
        SOL003ResponseException cause = (SOL003ResponseException) exception.getCause();

        assertThat(exception.getMessage()).isEqualTo("Unable to communicate with Grant Provider on [http://localhost:8080/grant/v1/grants/{grantId}] which gave status 500");
        assertThat(cause.getProblemDetails()).isNotNull();
        assertThat(cause.getProblemDetails().getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(cause.getProblemDetails().getDetail()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase() + ": " + TEST_EXCEPTION_MESSAGE);
    }

    @Test
    public void testGetGrantWithInvalidSuccessCode() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withCreatedEntity(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID)).body(loadFileIntoString("examples/GrantResource.json"))
                        .contentType(MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> grantDriver.getGrant(TEST_GRANT_ID))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Invalid status code [201 CREATED] received");
    }

    @Test
    public void testGetGrantWithInvalidResponseCode() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.MOVED_PERMANENTLY)
                        .location(URI.create(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID)));

        assertThatThrownBy(() -> grantDriver.getGrant(TEST_GRANT_ID))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("Invalid status code [301 MOVED_PERMANENTLY] received");
    }

    @Test
    public void testGetGrantWithEmptyResponseBodyForOk() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.OK));

        assertThatThrownBy(() -> grantDriver.getGrant(TEST_GRANT_ID))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("No response body");
    }

    @Test
    public void testGetGrantWithNonEmptyResponseBodyForAccepted() throws Exception {
        final MockRestServiceServer server = MockRestServiceServer.bindTo(grantDriver.getAuthenticatedRestTemplate()).build();

        server.expect(requestTo(TEST_SERVER_BASE_URL + GRANT_ENDPOINT + "/" + TEST_GRANT_ID))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.ACCEPTED).body(loadFileIntoString("examples/GrantResource.json"))
                        .contentType(MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> grantDriver.getGrant(TEST_GRANT_ID))
                .isInstanceOf(GrantProviderException.class)
                .hasMessage("No response body expected");
    }

}
