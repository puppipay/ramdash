'use strict';

var dashbitcore = module.exports;

// module information
dashbitcore.version = 'v' + require('./package.json').version;
dashbitcore.versionGuard = function(version) {
  if (version !== undefined) {
    var message = 'More than one instance of dashcore-lib found. ' +
      'Please make sure that you are not mixing instances of classes of the different versions of dashcore.';
    console.warn(message);
  }
};
dashbitcore.versionGuard(global._dashbitcore);
global._dashbitcore = dashbitcore.version;

// crypto
dashbitcore.crypto = {};
dashbitcore.crypto.BN = require('./lib/crypto/bn');
dashbitcore.crypto.ECDSA = require('./lib/crypto/ecdsa');
dashbitcore.crypto.Hash = require('./lib/crypto/hash');
dashbitcore.crypto.Random = require('./lib/crypto/random');
dashbitcore.crypto.Point = require('./lib/crypto/point');
dashbitcore.crypto.Signature = require('./lib/crypto/signature');

// encoding
dashbitcore.encoding = {};
dashbitcore.encoding.Base58 = require('./lib/encoding/base58');
dashbitcore.encoding.Base58Check = require('./lib/encoding/base58check');
dashbitcore.encoding.BufferReader = require('./lib/encoding/bufferreader');
dashbitcore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
dashbitcore.encoding.Varint = require('./lib/encoding/varint');

// utilities
dashbitcore.util = {};
dashbitcore.util.buffer = require('./lib/util/buffer');
dashbitcore.util.js = require('./lib/util/js');
dashbitcore.util.preconditions = require('./lib/util/preconditions');

// errors thrown by the library
dashbitcore.errors = require('./lib/errors');

// main bitcoin library
dashbitcore.Address = require('./lib/address');
dashbitcore.Block = require('./lib/block');
dashbitcore.MerkleBlock = require('./lib/block/merkleblock');
dashbitcore.BlockHeader = require('./lib/block/blockheader');
dashbitcore.HDPrivateKey = require('./lib/hdprivatekey.js');
dashbitcore.HDPublicKey = require('./lib/hdpublickey.js');
dashbitcore.Networks = require('./lib/networks');
dashbitcore.DashNetworks = require('./lib/dashnetworks');
dashbitcore.Opcode = require('./lib/opcode');
dashbitcore.PrivateKey = require('./lib/privatekey');
dashbitcore.PublicKey = require('./lib/publickey');
dashbitcore.Script = require('./lib/script');
dashbitcore.DashScript = require('./lib/dashscript');
dashbitcore.Transaction = require('./lib/transaction');
dashbitcore.GovObject = require('./lib/govobject');
dashbitcore.URI = require('./lib/uri');
dashbitcore.Unit = require('./lib/unit');
dashbitcore.Message = require('./lib/message')

// dependencies, subject to change
dashbitcore.deps = {};
dashbitcore.deps.bnjs = require('bn.js');
dashbitcore.deps.bs58 = require('bs58');
dashbitcore.deps.Buffer = Buffer;
dashbitcore.deps.elliptic = require('elliptic');
dashbitcore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
dashbitcore.Transaction.sighash = require('./lib/transaction/sighash');
