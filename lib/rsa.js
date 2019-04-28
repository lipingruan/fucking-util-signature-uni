'use strict';

const NodeRSA = require('./node-rsa');

const Signature = require ( './signature' );

module.exports = class Sub extends Signature {

  constructor ( ) {

    super ( );

    this.type = "RSA";

    this.keys = new NodeRSA ( );
  }

  setPublicKey ( key ) { this.keys.importKey ( key ); return this }

  setPrivateKey ( key ) { this.keys.importKey ( key ); return this }

  static generateKeys ( size=1024, type='pkcs8' ) {
  
    const key = new NodeRSA({b: size});

    const publicKeyType = type + "-public-pem", privateKeyType = type + "-private-pem";

    const publicKey = key.exportKey ( publicKeyType );
  
    const privateKey = key.exportKey ( privateKeyType );
  
    const result = { publicKey, privateKey };
  
    return result;
  }

  sign ( data, output='base64' ) {
  
    const result = this.keys.sign ( data, output, 'utf8' );
  
    return result;
  }
  
  verify ( data, signString, output='base64' ) {
  
    const result = this.keys.verify ( data, signString, 'utf8', output );
  
    return result;
  }
  
  encrypt ( data, output='base64' ) {
  
    const result = this.keys.encrypt ( data, output );
  
    return result;
  }
  
  decrypt ( cryptedData ) {
  
    const result = this.keys.decrypt ( cryptedData, 'utf8' );
  
    return result;
  }
}
