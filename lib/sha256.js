'use strict';

const hash = require ( 'js-sha256' );

const Signature = require ( './signature' );

const isNodeEnv = typeof process === 'object';

function transformArrayBufferToBase64 (buffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  for (var len = bytes.byteLength, i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

module.exports = class Sub extends Signature {

  constructor ( ) {

    super ( );

    this.type = "SHA256";
  }

  sign ( data, output ) {

    if ( output === 'hex' ) {

      return hash.sha256.hex ( data );
    } else {

      let ab = hash.sha256.arrayBuffer ( data );
    
      if ( isNodeEnv ) {
  
        return new Buffer ( ab ).toString ( 'base64' );
      } else {
  
        return transformArrayBufferToBase64 ( ab );
      }
    }
  }

  verify ( data, signString, output ) {

    const dataSignString = this.sign ( data, output );

    return dataSignString === signString;
  }
}