package org.etsi.sol003.lifecyclemanagement;

import java.time.OffsetDateTime;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "notificationType")
@JsonSubTypes({
        @JsonSubTypes.Type(value = VnfIdentifierCreationNotification.class, name = VnfIdentifierCreationNotification.TYPE),
        @JsonSubTypes.Type(value = VnfIdentifierDeletionNotification.class, name = VnfIdentifierDeletionNotification.TYPE),
        @JsonSubTypes.Type(value = VnfLcmOperationOccurenceNotification.class, name = VnfLcmOperationOccurenceNotification.TYPE)
})
public interface LifecycleManagementNotification {

    String getId();
    String getNotificationType();
    String getSubscriptionId();
    OffsetDateTime getTimeStamp();
    String getVnfInstanceId();
    LccnLinks getLinks();

}
