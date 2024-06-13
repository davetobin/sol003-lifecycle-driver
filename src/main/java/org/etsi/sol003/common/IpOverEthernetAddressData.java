package org.etsi.sol003.common;

import java.util.List;

import org.etsi.sol003.lifecyclemanagement.SubnetIpRange;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Represents network address data for IP over Ethernet.
 */
@Data
@JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@Schema(description = "Represents network address data for IP over Ethernet.")
public class IpOverEthernetAddressData {

    @Schema(name = "MAC Address", description = "MAC address. If this attribute is not present, it shall be chosen by the VIM.")
    private String macAddress;
    @Schema(name = "Segmentation Type", description = "Specifies the encapsulation type for the traffics coming in and out of the trunk subport.")
    private SegmentationType segmentationType;
    @Schema(name = "Segmentation Id", description = "Identification of the network segment to which the CP instance connects to.")
    private String segmentationId;
    @Schema(name = "IP Addresses", required = true, description = "List of IP addresses to assign to the CP instance. If this attribute is not present, no IP address shall be assigned.")
    private List<IpAddress> ipAddresses;

    /**
     * Represents IP address data for fixed or dynamic IP address assignment per subnet.
     */
    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    @Schema(description = "Represents IP address data for fixed or dynamic IP address assignment per subnet.")
    public static class IpAddress {

        @Schema(name = "Type", required = true, description = "The type of the IP addresses.")
        private IpAddressType type;
        @Schema(name = "Fixed Addresses", description = "Fixed addresses to assign (from the subnet defined by \"subnetId\" if provided).")
        private List<String> fixedAddresses;
        @Schema(name = "Number of Dynamic Addresses", description = "Number of dynamic addresses to assign (from the subnet defined by \"subnetId\" if provided).")
        private Integer numDynamicAddresses;
        @Schema(name = "IP Address Range", description = "An IP address range to be used, e.g. in case of egress connections. In case this attribute is present, IP addresses from the range will be used.")
        private SubnetIpRange addressRange;
        @Schema(name = "Subnet Id", description = "Subnet defined by the identifier of the subnet resource in the VIM. In case this attribute is present, IP addresses from that subnet will be assigned; otherwise, IP addresses not bound to a subnet will be assigned.")
        private String subnetId;

        public enum IpAddressType {
            IPV4, IPV6;
        }

    }
    public enum SegmentationType {
        /**
         * the subport uses VLAN as encapsulation type.
         */
         VLAN,

         /**
         * the subport gets its segmentation type from the network it is connected to.
         */
         INHERIT
   }

}
