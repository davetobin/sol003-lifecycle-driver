package com.accantosystems.stratoss.vnfmdriver.driver.impl;

import static com.accantosystems.stratoss.vnfmdriver.test.TestConstants.loadFileIntoString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.ExpectedCount.between;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

import java.util.List;

import org.etsi.sol003.packagemanagement.VnfPkgInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.client.MockRestServiceServer;

import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverConstants;
import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverProperties;
import com.accantosystems.stratoss.vnfmdriver.driver.SOL003ResponseException;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageNotFoundException;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageRepositoryDriver;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageRepositoryException;
import com.accantosystems.stratoss.vnfmdriver.model.AuthenticationType;
import com.accantosystems.stratoss.vnfmdriver.service.AuthenticatedRestTemplateService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({ "test" })
public class NexusVNFPackageRepositoryDriverTest {

    public static final String EMPTY_SEARCH_RESULTS = "{\"items\": [], \"continuationToken\": null}";
    @Autowired private VNFPackageRepositoryDriver vnfPackageDriver;
    @Autowired private VNFMDriverProperties vnfmDriverProperties;
    @Autowired private AuthenticatedRestTemplateService authenticatedRestTemplateService;
    @Autowired private ObjectMapper objectMapper;

    private MockRestServiceServer getMockRestServiceServer(VNFMDriverProperties vnfmDriverProperties) {
        return MockRestServiceServer.bindTo(authenticatedRestTemplateService.getRestTemplate(vnfmDriverProperties.getPackageManagement().getPackageRepositoryUrl(),
                                                                                             vnfmDriverProperties.getPackageManagement().getAuthenticationProperties())).build();
    }

    @Test
    public void testGetVnfPackage() throws Exception {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search/assets?repository=test-repository&keyword=*vMRF.zip*")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("examples/pkgMgmt-AssetSearch.json"), MediaType.APPLICATION_JSON));

        Resource vnfPackage = vnfPackageDriver.getVnfPackage("vMRF");
        assertThat(ByteStreams.toByteArray(vnfPackage.getInputStream())).isNotEmpty();
    }

    @Test
    public void testGetVnfPackageNotFound() {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search/assets?repository=test-repository&keyword=*not-present-id.zip*")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(EMPTY_SEARCH_RESULTS, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> vnfPackageDriver.getVnfPackage("not-present-id"))
                .isInstanceOf(VNFPackageNotFoundException.class)
                .hasMessage("VNF Package [not-present-id] not found in repository [http://does-not-exist:8081]");
    }

    @Test
    public void testGetVnfPackageNoConfiguredRepoUrl() {
        VNFMDriverProperties properties = new VNFMDriverProperties();
        properties.getPackageManagement().setPackageRepositoryUrl(null);
        VNFPackageRepositoryDriver vnfPackageDriver = new NexusVNFPackageRepositoryDriver(properties, authenticatedRestTemplateService, objectMapper);

        assertThatThrownBy(() -> vnfPackageDriver.getVnfPackage("vMRF"))
                .isInstanceOf(VNFPackageRepositoryException.class)
                .hasMessageStartingWith("A valid VNF Package Repository URL must be configured.");
    }

    @Test
    public void testQueryVnfPkgInfo() throws Exception {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(times(2), requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository&group=/group/vnfdId")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("examples/pkgMgmt-ComponentSearch.json"), MediaType.APPLICATION_JSON));

        server.expect(requestTo("http://does-not-exist:8081/repository/test-repository/group/vnfdId/vnfPackageId.pkgInfo")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("examples/vnfPackageId.pkgInfo"), MediaType.TEXT_PLAIN));

        // Create new instance of the driver to ensure we don't get accidental cache hits)
        final VNFPackageRepositoryDriver vnfPackageDriver = new NexusVNFPackageRepositoryDriver(vnfmDriverProperties, authenticatedRestTemplateService, objectMapper);

        List<VnfPkgInfo> vnfPkgInfoList = vnfPackageDriver.queryAllVnfPkgInfos("/group/vnfdId");
        assertThat(vnfPkgInfoList).hasSize(1);

        // Query for a second time and check we don't re-fetch the VnfPkgInfo (should be cached)
        vnfPkgInfoList = vnfPackageDriver.queryAllVnfPkgInfos("/group/vnfdId");
        assertThat(vnfPkgInfoList).hasSize(1);

        // Verify all expectations met
        server.verify();
    }

    @Test
    public void testQueryVnfPkgInfoNoGroupName() throws Exception {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(times(2), requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/pkgMgmt-ComponentSearch.json"), MediaType.APPLICATION_JSON));

        // This is optional due to the potential caching within the driver
        server.expect(between(0, 1), requestTo("http://does-not-exist:8081/repository/test-repository/group/vnfdId/vnfPackageId.pkgInfo")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), MediaType.TEXT_PLAIN));

        List<VnfPkgInfo> vnfPkgInfoList = vnfPackageDriver.queryAllVnfPkgInfos("");
        assertThat(vnfPkgInfoList).hasSize(1);

        // Query for a second time and check we don't re-fetch the VnfPkgInfo (should be cached)
        vnfPkgInfoList = vnfPackageDriver.queryAllVnfPkgInfos(null);
        assertThat(vnfPkgInfoList).hasSize(1);

        // Verify all expectations met
        server.verify();
    }

    @Test
    public void testQueryVnfPkgInfoWithAuthentication() throws Exception {
        VNFMDriverProperties properties = new VNFMDriverProperties();
        properties.getPackageManagement().setPackageRepositoryUrl("http://does-not-exist:8081");
        properties.getPackageManagement().setRepositoryName("test-repository");
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_TYPE, AuthenticationType.BASIC.toString());
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_USERNAME, "admin");
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_PASSWORD, "admin123");
        final MockRestServiceServer server = getMockRestServiceServer(properties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository&group=/group/vnfdId")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/pkgMgmt-ComponentSearch.json"), MediaType.APPLICATION_JSON));

        server.expect(requestTo("http://does-not-exist:8081/repository/test-repository/group/vnfdId/vnfPackageId.pkgInfo")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), MediaType.TEXT_PLAIN));

        VNFPackageRepositoryDriver vnfPackageDriver = new NexusVNFPackageRepositoryDriver(properties, authenticatedRestTemplateService, objectMapper);

        List<VnfPkgInfo> vnfPkgInfoList = vnfPackageDriver.queryAllVnfPkgInfos("/group/vnfdId");
        assertThat(vnfPkgInfoList).hasSize(1);
    }

    @Test
    public void testQueryVnfPkgInfoWithAuthenticationFailure() {
        VNFMDriverProperties properties = new VNFMDriverProperties();
        properties.getPackageManagement().setPackageRepositoryUrl("http://does-not-exist:8081");
        properties.getPackageManagement().setRepositoryName("test-repository");
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_TYPE, AuthenticationType.BASIC.toString());
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_USERNAME, "jack");
        properties.getPackageManagement().getAuthenticationProperties().put(VNFMDriverConstants.AUTHENTICATION_PASSWORD, "jack");
        final MockRestServiceServer server = getMockRestServiceServer(properties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository&group=/group/vnfdId")).andExpect(method(HttpMethod.GET))
              .andRespond(withUnauthorizedRequest());

        VNFPackageRepositoryDriver vnfPackageDriver = new NexusVNFPackageRepositoryDriver(properties, authenticatedRestTemplateService, objectMapper);

        assertThatThrownBy(() -> vnfPackageDriver.queryAllVnfPkgInfos("/group/vnfdId"))
                .isInstanceOf(SOL003ResponseException.class)
                .hasFieldOrPropertyWithValue("problemDetails.status", HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    public void testGetVnfPkgInfo() throws Exception {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository&keyword=*vnfPackageId.pkgInfo*")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/pkgMgmt-ComponentSearch.json"), MediaType.APPLICATION_JSON));

        // This is optional due to the potential caching within the driver
        server.expect(between(0, 1), requestTo("http://does-not-exist:8081/repository/test-repository/group/vnfdId/vnfPackageId.pkgInfo")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), MediaType.TEXT_PLAIN));

        VnfPkgInfo vnfPkgInfo = vnfPackageDriver.getVnfPkgInfo("vnfPackageId");
        assertThat(vnfPkgInfo).isNotNull();
    }

    @Test
    public void testGetVnfPkgInfoNotFound() {
        final MockRestServiceServer server = getMockRestServiceServer(vnfmDriverProperties);

        server.expect(requestTo("http://does-not-exist:8081/service/rest/v1/search?repository=test-repository&keyword=*not-present-id.pkgInfo*")).andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(EMPTY_SEARCH_RESULTS, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> vnfPackageDriver.getVnfPkgInfo("not-present-id"))
                .isInstanceOf(VNFPackageNotFoundException.class)
                .hasMessage("Cannot find package information for VNF package [not-present-id]");
    }

}
