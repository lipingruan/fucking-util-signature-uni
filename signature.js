'use strict';

const util = require ( './util' );

const MD5 = require('./lib/md5');
const SHA256 = require('./lib/sha256');
const RSA = require ( './lib/rsa' );

module.exports = class Signature {

  static get MD5 ( ) { return MD5 }
  static get SHA256 ( ) { return SHA256 }
  static get RSA ( ) { return RSA }

  constructor ( ) {
    
    this.formOptions = {
      signKey: 'sign',
      signTypeKey: 'signType',
      signSaltKey: 'key',
      ignoreKeys: [
        'sign', 'key'
      ],
      salt: ""
    };
  }

  copyFormOptions ( formOptions ) {

    let f0 = util.Extend ( { }, this.formOptions );

    let f1 = util.Extend ( f0, formOptions );

    return f1;
  }

  builder ( instance, options ) {

    return new SignatureBuilder ( this, instance, options );
  }

  md5 ( data, output ) {

    return this.builder ( new MD5 ( ), { data, output } );
  }

  sha256 ( data, output ) {

    return this.builder ( new SHA256 ( ), { data, output } );
  }

  rsa ( data, output ) {

    return this.builder ( new RSA ( ), { data, output } );
  }

  sign ( data, output, instance ) {
  
    let unsignedString = util.Type.parse.string ( data );

    let sign = instance.sign ( unsignedString, output );

    return sign;
  }

  verify ( data, signString, output, instance ) {

    return instance.verify ( data, signString, output );
  }
  
  /**
   * 
   * @param {any} any
   * @description
   * { a: 1, b: 2 }
   * => a=1&b=2
   */
  querystring ( any, formOptions ) {

    formOptions = formOptions || this.formOptions;

    let { ignoreKeys, signSaltKey, salt } = formOptions;

    let form = this.json ( any, formOptions );

    let keyValArray = 
    util.Str.querys.objToUrlKeyValArr ( form, ignoreKeys );

    if ( util.Type.empty ( salt ) ) { } else {

      keyValArray.push (
        util.Str.querys.mixKeyVal ( signSaltKey, salt ) )
    }

    let unsignedString = keyValArray.join ( '&' );

    return unsignedString;
  }

  json ( any, formOptions ) {

    if ( util.Type.string ( any ) ) {

      formOptions = formOptions || this.formOptions;

      let { ignoreKeys } = formOptions;

      let json = util.Str.querys.urlStrToObj ( any, ignoreKeys );

      return json;
    } else {

      return any;
    }
  }

  signForm ( any, output, instance, options ) {

    let formOptions = !options || options === this.formOptions 
      ? this.formOptions
      : this.copyFormOptions ( options );

    let { signKey, signTypeKey } = formOptions;

    let form = this.json ( any );

    if ( util.Type.empty ( signTypeKey ) ) { } else {

      form [ signTypeKey ] = instance.type;
    }

    let unsignedString = this.querystring ( form, formOptions );

    let sign = instance.sign ( unsignedString, output );

    form [ signKey ] = sign;

    let querystring = util.Str.querys.objToUrlStr ( form );

    return { querystring, form, sign };
  }

  verifyForm ( any, sign, output, instance, options ) {

    let formOptions = !options || options === this.formOptions 
      ? this.formOptions
      : this.copyFormOptions ( options );

    let { signKey } = formOptions;

    let form = this.json ( any );

    let unsignedString = this.querystring ( form, formOptions );

    sign = sign || form [ signKey ];

    return this.verify ( unsignedString, sign, output, instance );
  }

  static signJSON ( data, key ) {

    let signature = new this;

    return signature.signJSON ( data, key );
  }

  static verifyJSON ( data, key ) {

    let signature = new this;

    return signature.verifyJSON ( data, key );
  }

  /**
   * 
   * @param {JSON} data 
   * @param {String} key 
   * @deprecated
   */
  signJSON ( data, key ) {

    let { signTypeKey } = this.formOptions;

    let signType = data [ signTypeKey ];

    if ( signType === 'MD5' ) {

      return this.md5 ( data ).form ( { salt: key } ).digest ( );
    } else if ( signType === 'SHA256' ) {

      return this.sha256 ( data ).form ( { salt: key } ).digest ( );
    } else if ( signType === 'RSA' ) {

      return this.rsa ( data ).form ( { salt: key } ).digest ( );
    } else {

      let message = 'Not support algorithm: ' + signType;

      throw new Error ( message );
    }
  }

  /**
   * 
   * @param {JSON} data 
   * @param {Stirng} key 
   * @deprecated
   */
  verifyJSON ( data, key ) {
    
    let { signTypeKey } = this.formOptions;

    let signType = data [ signTypeKey ];

    if ( signType === 'MD5' ) {

      return this.md5 ( data ).form ( { salt: key } ).verify ( );
    } else if ( signType === 'SHA256' ) {

      return this.sha256 ( data ).form ( { salt: key } ).verify ( );
    } else if ( signType === 'RSA' ) {

      return this.rsa ( data ).form ( { salt: key } ).verify ( );
    } else {

      let message = 'Not support algorithm: ' + signType;

      throw new Error ( message );
    }
  }
}

class SignatureBuilder {

  constructor ( signature, instance, options={ } ) {

    let { data, output, formOptions } = options;

    this.options = {
      output: 'base64',
      form: false,
      formOptions: { }
    };

    this.signature = signature;

    this.instance = instance;

    this
    .data ( data )
    .output ( output )
    .formOptions ( formOptions )
  }

  update ( data ) {

    return this.data ( data );
  }

  data ( data ) {

    this.options.data = data;

    return this;
  }

  output ( output ) {

    this.options.output = output;

    return this;
  }

  form ( any ) {

    this.options.form = any === true || util.Type.object ( any );

    if ( util.Type.object ( any ) ) {

      this.formOptions ( any );
    } else { }

    return this;
  }

  formOptions ( options ) {

    let { formOptions } = this.options;

    this.options.formOptions = util.Extend ( { }, formOptions );

    util.Extend ( this.options.formOptions, options );

    return this;
  }

  setPublicKey ( key ) {

    if ( util.Type.function ( this.instance.setPublicKey ) ) {

      this.instance.setPublicKey ( key );
    }

    return this;
  }

  setPrivateKey ( key ) {

    if ( util.Type.function ( this.instance.setPrivateKey ) ) {

      this.instance.setPrivateKey ( key );
    }

    return this;
  }

  digest ( outputArg ) {
    
    let { data, form, output, formOptions } = this.options;

    let finalOutput = outputArg || output;

    if ( form === true ) {

      return this.signature.signForm ( 
        data, finalOutput, this.instance, formOptions );
    } else {

      return this.signature.sign ( 
        data, finalOutput, this.instance );
    }
  }

  verify ( sign, outputArg ) {

    let { data, form, output, formOptions } = this.options;

    let finalOutput = outputArg || output;

    if ( form === true ) {

      return this.signature.verifyForm ( 
        data, sign, finalOutput, this.instance, formOptions );
    } else {

      return this.signature.verify ( 
        data, sign, finalOutput, this.instance );
    }
  }
}
