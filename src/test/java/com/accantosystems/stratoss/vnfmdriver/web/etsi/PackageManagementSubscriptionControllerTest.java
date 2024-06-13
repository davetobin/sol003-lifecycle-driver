package com.accantosystems.stratoss.vnfmdriver.web.etsi;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;

import org.etsi.sol003.common.SubscriptionAuthentication;
import org.etsi.sol003.packagemanagement.PackageOperationalStateType;
import org.etsi.sol003.packagemanagement.PkgmNotificationsFilter;
import org.etsi.sol003.packagemanagement.PkgmSubscription;
import org.etsi.sol003.packagemanagement.PkgmSubscriptionRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;

public class PackageManagementSubscriptionControllerTest {

    @Test
    public void testSubscriptions() throws Exception {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();
        final PackageManagementSubscriptionController controller = new PackageManagementSubscriptionController();

        final PkgmSubscriptionRequest subscriptionRequest = new PkgmSubscriptionRequest();
        subscriptionRequest.setCallbackUri("http://localhost:8080/call-me-back");
        PkgmNotificationsFilter filter = new PkgmNotificationsFilter();
        filter.setOperationalStates(Collections.singletonList(PackageOperationalStateType.ENABLED));
        subscriptionRequest.setFilter(filter);
        SubscriptionAuthentication authentication = new SubscriptionAuthentication();
        authentication.setAuthType(SubscriptionAuthentication.AuthType.BASIC);
        SubscriptionAuthentication.BasicParameters basicAuthenticationParameters = new SubscriptionAuthentication.BasicParameters();
        basicAuthenticationParameters.setUsername("jack");
        basicAuthenticationParameters.setPassword("jack");
        authentication.setParamsBasic(basicAuthenticationParameters);
        subscriptionRequest.setAuthentication(authentication);

        // First, create the subscription
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", PackageManagementSubscriptionController.API_PATH);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest));
        servletRequest.setContent(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(subscriptionRequest));
        ResponseEntity<PkgmSubscription> responseEntity = controller.createNewSubscription(subscriptionRequest, servletRequest);

        assertThat(responseEntity).isNotNull();
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(responseEntity.getBody()).isNotNull();
        assertThat(responseEntity.getBody().getId()).isNotNull();
        assertThat(responseEntity.getHeaders().getLocation()).hasPath(PackageManagementSubscriptionController.API_PATH + "/" + responseEntity.getBody().getId());
        final String subscriptionId = responseEntity.getBody().getId();

        // Second, attempt to get that subscription
        responseEntity = controller.getSubscription(subscriptionId);

        assertThat(responseEntity).isNotNull();
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(responseEntity.getBody()).isNotNull();
        assertThat(responseEntity.getBody().getId()).isEqualTo(subscriptionId);

        // Third, delete the subscription
        ResponseEntity<Void> deleteResponseEntity = controller.deleteSubscription(subscriptionId);

        assertThat(deleteResponseEntity).isNotNull();
        assertThat(deleteResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(deleteResponseEntity.getBody()).isNull();

        // Finally, ensure the subscription can no longer be found
        responseEntity = controller.getSubscription(subscriptionId);

        assertThat(responseEntity).isNotNull();
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(responseEntity.getBody()).isNull();
    }

}