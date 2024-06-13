package org.etsi.sol003.lifecyclemanagement;

/**
 * the permitted values to represent the result of executing an LCM coordination action.
 */
public enum LcmCoordResultType {

    /**
     * The related LCM operation shall be continued, staying in the state "PROCESSING".
     */
    CONTINUE,

    /**
     * The related LCM operation shall be aborted by transitioning into the state "FAILED_TEMP".
     */
    ABORT,

    /**
     * The coordination action has been cancelled upon request of the API consumer, i.e. the VNFM.
     * The related LCM operation shall be aborted by transitioning into the state "FAILED_TEMP".
     */
    CANCELLED

    
}
