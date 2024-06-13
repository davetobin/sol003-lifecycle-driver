/*
 This is the generic message creation logic for ChangeCurrentVnfPkgRequest messages based on the 3.5.1 version of the ETSI SOL003 specification
 */
 logger.debug('Generating ChangeCurrentVnfPkgRequest message for ETSI SOL003 v3.5.1');
 load('classpath:scripts/lib.js');
 
 // Create the message object to be returned
 var message = {extVirtualLinks: [], vimConnectionInfo: {}, extManagedVirtualLinks: [],additionalParams: {},vnfConfigurableProperties: {},extensions: {}};

 // Set the standard message properties
// The VNFD id is required, the other fields are optional
setPropertyIfNotNull(executionRequest.properties, message, 'vnfdId');
 
 for (var key in executionRequest.getProperties()) {
     if (key.startsWith('extManagedVirtualLinks.') || key.startsWith('extVirtualLinks.') || key.startsWith('vimConnectionInfo.') || key.startsWith('additionalParams.') || key.startsWith('vnfConfigurableProperties.') || key.startsWith('extensions.')) {
         // print('Got property [' + key + '], value = [' + executionRequest.properties[key] + ']');
         addProperty(message, key, executionRequest.properties[key]);
     }
 }
 
 logger.debug('Message generated successfully');
 // Turn the message object into a JSON string to be returned back to the Java driver
 JSON.stringify(message);