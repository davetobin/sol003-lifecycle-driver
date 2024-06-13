package com.accantosystems.stratoss.vnfmdriver.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.etsi.sol003.granting.Grant;
import org.etsi.sol003.granting.GrantRequest;
import org.etsi.sol003.lifecyclemanagement.LcmOperationType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverProperties;
import com.accantosystems.stratoss.vnfmdriver.driver.GrantDriver;
import com.accantosystems.stratoss.vnfmdriver.driver.GrantProviderException;
import com.accantosystems.stratoss.vnfmdriver.model.GrantCreationResponse;
import com.accantosystems.stratoss.vnfmdriver.web.etsi.BadRequestException;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({ "test" })
public class GrantServiceTest {

    @MockBean
    private GrantDriver grantDriver;

    @Autowired
    private GrantService grantService;

    @Autowired
    private VNFMDriverProperties vnfmDriverProperties;

    @Test
    public void testRequestGrantBadRequest() {

        assertThatThrownBy(() -> grantService.requestGrant(null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Grant Request cannot be null");

        GrantRequest request = new GrantRequest();
        assertThatThrownBy(() -> grantService.requestGrant(request))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Grant request missing vnfInstanceId");

        request.setVnfInstanceId("vnfInstId");
        assertThatThrownBy(() -> grantService.requestGrant(request))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Grant request for vnfInstanceId [vnfInstId] contained a null operation");
    }

    @Test
    public void testRequestGrantAutomatic() throws GrantRejectedException, GrantProviderException {

        // setup automatic grants
        vnfmDriverProperties.getGrant().setAutomatic(true);

        GrantRequest grantRequest = createValidGrantRequest();
        GrantCreationResponse retGrantCreationResponse = grantService.requestGrant(grantRequest);
        assertThat(retGrantCreationResponse.getGrant().getId()).isNotEmpty();
        assertThat(retGrantCreationResponse.getGrantId()).isNotEmpty();

    }

    @Test
    public void testRequestGrantNonAutomaticSync() throws GrantRejectedException, GrantProviderException {

        // setup non-automatic grants and mock a response from the grant driver
        vnfmDriverProperties.getGrant().setAutomatic(false);
        Grant grant = createValidGrantResponse();
        GrantCreationResponse grantCreationResponse = new GrantCreationResponse(grant);
        when(grantDriver.requestGrant(any(GrantRequest.class))).thenReturn(grantCreationResponse);

        GrantRequest grantRequest = createValidGrantRequest();
        GrantCreationResponse retGrantCreationResponse = grantService.requestGrant(grantRequest);
        assertThat(retGrantCreationResponse.getGrant()).isEqualTo(grant);
        assertThat(retGrantCreationResponse.getGrantId()).isEqualTo(grant.getId());

    }

    @Test
    public void testRequestGrantNonAutomaticAsync() throws GrantRejectedException, GrantProviderException {

        // setup non-automatic grants and mock a response from the grant driver
        vnfmDriverProperties.getGrant().setAutomatic(false);
        Grant grant = createValidGrantResponse();
        GrantCreationResponse grantCreationResponse = new GrantCreationResponse(grant.getId());
        when(grantDriver.requestGrant(any(GrantRequest.class))).thenReturn(grantCreationResponse);

        GrantRequest grantRequest = createValidGrantRequest();
        GrantCreationResponse retGrantCreationResponse = grantService.requestGrant(grantRequest);
        assertThat(retGrantCreationResponse.getGrant()).isNull();
        assertThat(retGrantCreationResponse.getGrantId()).isEqualTo(grant.getId());

    }

    @Test
    public void testGetGrantBadRequest() {

        assertThatThrownBy(() -> grantService.getGrant(null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("grantId cannot be null");
    }

    @Test
    public void testGetGrantAutomatic() throws GrantRejectedException, GrantProviderException {

        // setup automatic grants
        vnfmDriverProperties.getGrant().setAutomatic(true);

        String grantId = UUID.randomUUID().toString();
        Grant retGrant = grantService.getGrant(grantId);
        assertThat(retGrant).isNotNull();
        assertThat(retGrant.getId()).isNotEmpty();

    }

    @Test
    public void testGetGrantNonAutomaticDecisionMade() throws GrantRejectedException, GrantProviderException {

        // setup non-automatic grants and mock a response from the grant driver
        vnfmDriverProperties.getGrant().setAutomatic(false);
        Grant grant = createValidGrantResponse();
        when(grantDriver.getGrant(eq(grant.getId()))).thenReturn(grant);

        Grant retGrant = grantService.getGrant(grant.getId());
        assertThat(retGrant).isEqualTo(grant);

    }

    @Test
    public void testGetGrantNonAutomaticNoDecisionMade() throws GrantRejectedException, GrantProviderException {

        // setup non-automatic grants and mock a response from the grant driver
        vnfmDriverProperties.getGrant().setAutomatic(false);
        Grant grant = createValidGrantResponse();
        when(grantDriver.getGrant(eq(grant.getId()))).thenReturn(null);

        Grant retGrant = grantService.getGrant(grant.getId());
        assertThat(retGrant).isNull();

    }

    private GrantRequest createValidGrantRequest() {
        GrantRequest request = new GrantRequest();
        request.setVnfInstanceId(UUID.randomUUID().toString());
        request.setOperation(LcmOperationType.INSTANTIATE);
        return request;
    }

    private Grant createValidGrantResponse() {
        Grant grant = new Grant();
        grant.setId(UUID.randomUUID().toString());
        return grant;
    }
}
