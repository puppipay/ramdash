'use strict';

var _ = require('lodash');
var inherits = require('inherits');
var Input = require('./input');
var Output = require('../output');
var $ = require('../../util/preconditions');

var Script = require('../../script');
var Signature = require('../../crypto/signature');
var Sighash = require('../sighash');
var PublicKey = require('../../publickey');
var BufferUtil = require('../../util/buffer');

/**
 * @constructor
 */
function CompositeScriptHashInput(input, compinputs, threshold ) {
  Input.apply(this, arguments);
  var self = this;
  this.compInputs = compinputs;
  this.threshold = threshold;
  this.redeemScript = Script.buildCompositeOut(this.compInputs, threshold);

  $.checkState(Script.buildScriptHashOut(this.redeemScript).equals(this.output.script),
               'Provided comp inputs don\'t hash to the provided output');
  this.threshold = threshold;
  // Empty array of signatures
}
inherits(CompositeScriptHashInput, Input);

CompositeScriptHashInput.prototype.toObject = function() {
  var obj = Input.prototype.toObject.apply(this, arguments);
  obj.threshold = this.threshold;
  obj.compInputs = this.compInputs.toString();
  return obj;
};

CompositeScriptHashInput.prototype.clearSignatures = function() {
  this._updateScript();
};

CompositeScriptHashInput.prototype._updateScript = function() {
  this.setScript(Script.buildP2SHCompositeIn(
    this.compInputs,
    this.threshold,
    { cachedMultisig: this.redeemScript }
  ));
  return this;
};



CompositeScriptHashInput.OPCODES_SIZE = 7; // serialized size (<=3) + 0 .. N .. M OP_CHECKMULTISIG
CompositeScriptHashInput.PUBKEY_SIZE = 34; // size (1) + DER (<=33)

CompositeScriptHashInput.prototype._estimateSize = function() {
  return CompositeScriptHashInput.OPCODES_SIZE +
    this.compInputs.length * CompositeScriptHashInput.PUBKEY_SIZE;
};

module.exports = CompositeScriptHashInput;
