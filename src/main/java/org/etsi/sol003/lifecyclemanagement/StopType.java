package org.etsi.sol003.lifecyclemanagement;

public enum StopType {

    /**
     * The VNFM will shut down the VNF and release the resources immediately after accepting the request.
     */
    FORCEFUL,

    /**
     * The VNFM will first arrange to take the VNF out of service after accepting the request. Once the operation of taking the VNF out of service finishes
     * (irrespective of whether it has succeeded or failed) or once the timer value specified in the "gracefulTerminationTimeout" attribute expires,
     * the VNFM will shut down the VNF and release the resources.
     */
    GRACEFUL

}
