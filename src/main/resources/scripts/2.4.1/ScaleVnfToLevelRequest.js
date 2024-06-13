/*
 This is the generic message creation logic for ScaleVnfToLevelRequest messages based on the 2.4.1 version of the ETSI SOL003 specification
 */
logger.debug('Generating ScaleVnfToLevelRequest message for ETSI SOL003 v2.4.1');
load('classpath:scripts/lib.js');

// Create the message object to be returned
var message = {scaleInfo: [], additionalParams: {}};

// Set the standard message properties
setPropertyIfNotNull(executionRequest.properties, message, 'instantiationLevelId');

for (var key in executionRequest.getProperties()) {
    if (key.startsWith('additionalParams.') || key.startsWith('scaleInfo.')) {
        // print('Got property [' + key + '], value = [' + executionRequest.properties[key] + ']');
        addProperty(message, key, executionRequest.properties[key]);
    }
}

logger.debug('Message generated successfully');
// Turn the message object into a JSON string to be returned back to the Java driver
JSON.stringify(message);