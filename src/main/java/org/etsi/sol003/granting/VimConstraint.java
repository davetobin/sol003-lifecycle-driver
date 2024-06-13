package org.etsi.sol003.granting;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * This type provides information regarding a VIM selection constraint. A set of such constraints may be sent by the VNFM to the NFVO to influence the VIM selection decisions made by the NFVO as part
 * of the granting process.
 */
@Data
@JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@Schema(description = "Represents a resource placement constraint.")
public class VimConstraint {

    @Schema(name = "Same Resource Group", description = "If present and set to true, this signals that the constraint applies not only to the same VIM connection, but also to the same infrastructure resource group.")
    private boolean sameResourceGroup;
    @JsonProperty("resource")
    @Schema(name = "References to Resources", required = true, description = "References to resources in the constraint rule. The NFVO shall ensure that all resources in this list are managed through the same VIM connection. If \"sameResourceGroup\" is set to true, the NFVO shall further ensure that all resources in this list are part of the same infrastructure resource group in that VIM connection.")
    private List<ConstraintResourceRef> resources;

}
