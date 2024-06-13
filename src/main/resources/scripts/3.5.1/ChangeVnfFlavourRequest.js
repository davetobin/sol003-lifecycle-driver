/*
 This is the generic message creation logic for ChangeVnfFlavourRequest messages based on the 3.5.1 version of the ETSI SOL003 specification
 */
logger.debug('Generating ChangeVnfFlavourRequest message for ETSI SOL003 v3.5.1');
load('classpath:scripts/lib.js');

// Create the message object to be returned
var message = {extVirtualLinks: {}, extManagedVirtualLinks: {}, vimConnectionInfo: {}, additionalParams: {}, extensions: {}, vnfConfigurableProperties: {}};

// Set the standard message properties
// The flavourId is required, the other fields are optional
message.newFlavourId = executionRequest.properties.flavourId;
setPropertyIfNotNull(executionRequest.properties, message, 'instantiationLevelId');
setPropertyIfNotNull(executionRequest.properties, message, 'localizationLanguage');

for (var key in executionRequest.getProperties()) {
    if (key.startsWith('additionalParams.') || key.startsWith('extVirtualLinks.') || key.startsWith('extManagedVirtualLinks.') || key.startsWith('vimConnectionInfo.') || key.startsWith('extensions.') || key.startsWith('vnfConfigurableProperties.')) {
        // print('Got property [' + key + '], value = [' + executionRequest.properties[key] + ']');
        addProperty(message, key, executionRequest.properties[key]);
    }
}

logger.debug('Message generated successfully');
// Turn the message object into a JSON string to be returned back to the Java driver
JSON.stringify(message);