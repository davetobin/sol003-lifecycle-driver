package org.etsi.sol003.lifecyclemanagement;

public enum LcmOpOccNotificationVerbosityType {

    /**
     * This signals a full notification which contains all change details.
     */
    FULL,

    /**
     * This signals a short notification which omits large-volume change details to reduce the size of
    *  data to be sent via the notification mechanism.
     */
    SHORT

}