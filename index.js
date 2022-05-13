import crypto from 'crypto';
import fs from 'fs';
import helmet from "helmet";
import http from 'http';
import https from 'https';
import cors from 'cors';
import cron from 'node-cron';
import dotenv from 'dotenv';
import express from 'express';
import log4js from 'log4js';
import nedb from 'nedb-promises';
import path from 'path';
import randomstring from 'randomstring';
import str2ab from 'str2ab';

import FSL from '@s1r-j/fido2server-lib';
const {
  AttestationCreationOptionsBuilder,
  AttestationExpectationBuilder,
  AttestationResponseVerifier,
  AttestationResponseParser,
  AssertionRequestOptionsBuilder,
  AssertionExpectationBuilder,
  AssertionResponseVerifier,
  AssertionResponseParser,
} = FSL;


import RequestValidateUtil from './util/requestValidateUtil.js';
import MdsUtil from './util/mdsUtil.js';

dotenv.config();

const RP_ORIGIN = new URL(process.env.SCHEME + '://' + process.env.HOSTNAME + ':' + process.env.PORT);
const RP_ID = RP_ORIGIN.hostname;
const RP_NAME = process.env.RP_NAME || RP_ID;
const ALGS = (process.env.ALGS || '-7').split(',').map(a => Number(a));

// log
log4js.configure({
  appenders: {
    fido2: {
      type: 'file',
      filename: process.env.LOG_FILE || './log/app.log',
    }
  },
  categories: {
    default: {
      appenders: ['fido2'],
      level: process.env.LOG_LEVEL || 'warn'
    }
  }
});
const logger = log4js.getLogger('fido2');

// db
const datastore = nedb.create(process.env.DB_FILE || './data/database.db');

// cron
if (cron.validate(process.env.DB_RESET)) {
  console.log(`Set DB reset cron: ${process.env.DB_RESET}`);
  cron.schedule(process.env.DB_RESET, () => {
    fs.writeFileSync(process.env.DB_FILE || './data/database.db', '');
  });
}
if (cron.validate(process.env.LOG_ROTATE)) {
  console.log(`Set log rotate cron: ${process.env.LOG_ROTATE}`);
  cron.schedule(process.env.LOG_ROTATE, () => {
    fs.writeFileSync(process.env.LOG_FILE || './log/app.log', '');
  });
}

// FIDO metadata
let addonEntries = [];
if (process.env.FIDO_METADATA_DIR) {
  const fileNames = fs.readdirSync(process.env.FIDO_METADATA_DIR);
  addonEntries = fileNames.map(fn => {
    if (fn === '.gitkeep') {
      return [];
    }
    const filepath = path.resolve(process.env.FIDO_METADATA_DIR, fn);
    const stats = fs.lstatSync(filepath);
    if (!stats.isFile()) {
      return [];
    }
    const file = fs.readFileSync(filepath, 'utf-8');
    try {
      const json = JSON.parse(file);
      if (Array.isArray(json)) {
        return json;
      } else {
        return [json];
      }
    } catch (err) {
      console.log(`${fn} is not JSON file.`);
      return [];
    }
  }).flat();
}
const mdsUtil = new MdsUtil(addonEntries);

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    'script-src': ["'self'", "'unsafe-inline'", "code.jquery.com"],
  }
}));
app.use(cors({
  "origin": "*",
  "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
  "preflightContinue": false,
  "optionsSuccessStatus": 204
}))

app.set("view engine", "ejs");
app.set("views", path.resolve('./views'));

const options = {
  key: process.env.PRIV_KEY ? fs.readFileSync(path.resolve(process.env.PRIV_KEY)) : null, // './ssl/privkey.pem'
  cert: process.env.CERT ? fs.readFileSync(path.resolve(process.env.CERT)) : null, // './ssl/fullchain.pem'
};

app.get('/hello', function (req, res) {
  // for test
  logger.info('/hello is called.');
  res.status(200).end('Hello, world.');
});

app.get('/', function (req, res) {
  const data = {
    vendorName: RP_NAME,
    serverURL: RP_ORIGIN.origin,
  };
  res.render("index.ejs", data);
});

app.post('/attestation/options', async (req, res) => {
  const requestId = randomstring.generate(10);
  logger.info({
    requestId,
    message: '/attestation/options is called.'
  });
  logger.trace({
    requestId,
    message: req.body
  });

  try {
    RequestValidateUtil.attestationOptions(req);

    let user = await datastore.findOne({
      type: 'user',
      username: req.body.username,
    });
    if (user == null) {
      const userId = randomstring.generate(10);
      await datastore.insert({
        type: 'user',
        userId,
        username: req.body.username,
        displayName: req.body.displayName,
      });
      user = await datastore.findOne({
        type: 'user',
        userId,
      });
    }
    const credentials = await datastore.find({
      type: 'credential',
      userId: user.userId,
    }).exec();
    const excludes = credentials.map(c => {
      return {
        type: 'public-key',
        id: str2ab.base64url2arraybuffer(c.credentialId),
        transports: c.transports,
      };
    });

    const challenge = str2ab.buffer2arraybuffer(crypto.randomBytes(64));
    const options = new AttestationCreationOptionsBuilder({
      rp: {
        id: RP_ID,
        name: RP_NAME,
      },
      user: {
        id: str2ab.string2arraybuffer(user.userId),
        name: req.body.username,
        displayName: req.body.displayName,
      },
      challenge,
      pubKeyCredParams: ALGS.map(alg => {
        return {
          type: 'public-key',
          alg,
        };
      }),
      timeout: 60000, // 60 sec
      excludeCredentials: excludes,
      authenticatorSelection: {
        ...req.body.authenticatorSelection,
        residentKey: (req.body.authenticatorSelection != null && req.body.authenticatorSelection.requireResidentKey) ? 'required' : undefined,
      },
      attestation: req.body.attestation,
    }).buildEncode();
    await datastore.insert({
      type: 'challenge',
      challenge: str2ab.arraybuffer2base64url(challenge),
      userId: user.userId,
      path: 'attestation',
    });
    logger.trace({
      requestId,
      message: options
    });

    res.status(200).json({
      ...options,
      extensions: {
        ...(req.body.extensions || {}),
      },
      status: 'ok',
      errorMessage: '',
    });
  } catch (err) {
    logger.error({
      requestId,
      message: err
    });
    res.status(500).json({
      status: 'failed',
      errorMessage: `${requestId} ${err.message}`,
    });
  }
});

app.post('/attestation/result', async (req, res) => {
  const requestId = randomstring.generate(10);
  logger.info({
    requestId,
    message: '/attestation/result is called.',
  });
  logger.trace({
    requestId,
    message: req.body
  });

  try {
    RequestValidateUtil.attestationResult(req);

    const parsed = AttestationResponseParser.parse({
      id: req.body.id,
      response: {
        attestationObject: str2ab.base64url2arraybuffer(req.body.response.attestationObject),
        clientDataJSON: str2ab.base64url2arraybuffer(req.body.response.clientDataJSON),
        transports: req.body.response.transports,
      },
      type: req.body.type,
    });
    if (parsed.challenge == null) {
      throw new Error('cannot parse challenge');
    }
    const challengeRecord = await datastore.findOne({
      type: 'challenge',
      path: 'attestation',
      challenge: parsed.challenge.base64url,
    });
    let isSuccess = false;
    try {
      const {
        challenge,
        userId,
      } = challengeRecord;
      let useMetadataService = false;
      let mdsEntry = null;
      if (parsed.aaguid != null && parsed.aaguid.uuid != null && parsed.aaguid.uuid !== '00000000-0000-0000-0000-000000000000') {
        mdsEntry = await mdsUtil.findEntry(parsed.aaguid.uuid);
        if (mdsEntry != null) {
          useMetadataService = true;
        }
      }
      const expectation = new AttestationExpectationBuilder({
        challenge: str2ab.base64url2arraybuffer(challenge),
        origin: RP_ORIGIN.origin,
        rpId: RP_ID,
        algs: ALGS,
        useMetadataService,
        metadataEntry: mdsEntry,
      }).build();

      const verifier = new AttestationResponseVerifier({
        id: req.body.id,
        response: {
          attestationObject: str2ab.base64url2arraybuffer(req.body.response.attestationObject),
          clientDataJSON: str2ab.base64url2arraybuffer(req.body.response.clientDataJSON),
          transports: req.body.response.transports,
        },
        type: req.body.type
      }, expectation);
      const result = await verifier.verify();
      logger.info({
        requestId,
        message: JSON.stringify(result, null, 2),
      });
      if (result.verification) {
        const aaguid = result.aaguid.uuid;
        if (aaguid !== '00000000-0000-0000-0000-000000000000') {
          const entry = await mdsUtil.findEntry(aaguid);
          await mdsUtil.verifyEntry(entry, 'sha256', result.attestationTypes || []);
        }

        await datastore.insert({
          type: 'credential',
          credentialId: result.credentialId.base64url,
          credential: result.pem,
          signCount: result.signCount,
          aaguid: result.aaguid.uuid,
          transports: req.body.response.transports || [],
          userId,
        });
        await datastore.remove({
          type: 'challenge',
          challenge,
        });
        isSuccess = true;
      } else {
        isSuccess = false;
      }
    } catch (err) {
      isSuccess = false;
      throw err;
    }

    if (isSuccess) {
      res.status(200).json({
        status: 'ok',
        errorMessage: '',
      });
    } else {
      throw new Error('Register is rejected.');
    }
  } catch (err) {
    logger.error({
      requestId,
      message: err
    });
    res.status(500).json({
      status: 'failed',
      errorMessage: `${requestId} ${err.message}`,
    });
  }
});

app.post('/assertion/options', async (req, res) => {
  const requestId = randomstring.generate(10);
  logger.info({
    requestId,
    message:'/assertion/options is called.'
  });
  logger.trace({
    requestId,
    message: req.body
  });

  try {
    RequestValidateUtil.assertionOptions(req);

    const user = await datastore.findOne({
      type: 'user',
      username: req.body.username,
    });
    if (user == null) {
      throw new Error(`user is not found: ${req.body.username}`);
    }
    const credentials = await datastore.find({
      type: 'credential',
      userId: user.userId,
    }).exec();

    const options = AssertionRequestOptionsBuilder.easyCreate({
      rpId: RP_ID,
      userVerification: req.body.userVerification,
    }).buildEncode();

    options.allowCredentials = credentials.map(c => {
      return {
        type: 'public-key',
        id: c.credentialId,
        transports: c.transports || [],
      };
    });
    logger.info({
      requestId,
      message: options
    });

    const challenge = options.challenge;
    await datastore.insert({
      type: 'challenge',
      challenge,
      path: 'assertion',
      userId: user.userId,
      userVerification: req.body.userVerification,
    });

    res.status(200).json({
      ...options,
      extensions: {
        ...(req.body.extensions || {}),
      },
      status: 'ok',
      errorMessage: '',
    });
  } catch (err) {
    logger.error({
      requestId,
      message: err
    });
    res.status(500).json({
      status: 'failed',
      errorMessage: `${requestId} ${err.message}`,
    });
  }
});

app.post('/assertion/result', async (req, res) => {
  const requestId = randomstring.generate(10);
  logger.info({
    requestId,
    message: '/assertion/result is called.'
  });
  logger.trace({
    requestId,
    message: req.body
  });

  try {
    RequestValidateUtil.assertionResult(req);

    const parsed = AssertionResponseParser.parse({
      id: req.body.id,
      response: {
        clientDataJSON: str2ab.base64url2arraybuffer(req.body.response.clientDataJSON),
        authenticatorData: str2ab.base64url2arraybuffer(req.body.response.authenticatorData),
        signature: str2ab.base64url2arraybuffer(req.body.response.signature),
        userHandle: req.body.response.userHandle != null ? str2ab.base64url2arraybuffer(req.body.response.userHandle) : undefined,
      },
      type: req.body.type,
    });

    const challengeRecord = await datastore.findOne({
      type: 'challenge',
      challenge: parsed.challenge.base64url,
      path: 'assertion',
    }).exec();
    const {
      challenge,
      userId,
      userVerification,
    } = challengeRecord;

    const credential = await datastore.findOne({
      type: 'credential',
      credentialId: parsed.credentialId.base64url,
      userId,
    });
  
    let flags = new Set();
    if (userVerification === 'required') {
      flags.add('UserVerified');
    }
    const expectation = new AssertionExpectationBuilder({
      credentialPublicKey: credential.credential,
      challenge: str2ab.base642arraybuffer(challenge),
      origin: RP_ORIGIN.origin,
      rpId: RP_ID,
      flags,
      storedSignCount: credential.signCount,
      strictSignCount: true,
    }).build();

    let isSuccess = false;
    try {

      const verifier = new AssertionResponseVerifier({
        id: req.body.id,
        response: {
          clientDataJSON: str2ab.base64url2arraybuffer(req.body.response.clientDataJSON),
          authenticatorData: str2ab.base64url2arraybuffer(req.body.response.authenticatorData),
          signature: str2ab.base64url2arraybuffer(req.body.response.signature),
          userHandle: req.body.response.userHandle != null ? str2ab.base64url2arraybuffer(req.body.response.userHandle) : undefined,
        },
        type: req.body.type,
      }, expectation);
      const result = await verifier.verify();
      logger.info({
        requestId,
        message: JSON.stringify(result, null, 2),
      });
      if (result.verification) {
        await datastore.update({
          type: 'credential',
          credentialId: credential.credentialId,
          userId,
        }, {
          $set: { signCount: result.signCount },
        }, {});
        await datastore.remove({
          type: 'challenge',
          challenge,
        });
        isSuccess = true;
      } else {
        isSuccess = false;
      }
    } catch (err) {
      isSuccess = false;
      throw err;
    }

    if (isSuccess) {
      res.status(200).json({
        status: 'ok',
        errorMessage: '',
      });  
    } else {
      throw new Error('Verification is failed.');
    }
  } catch (err) {
    logger.error({
      requestId,
      message: err
    });
    res.status(500).json({
      status: 'failed',
      errorMessage: `${requestId} ${err.message}`,
    });
  }
});

let httpServer;
if (options.cert != null && options.key != null) {
  httpServer = https.createServer(options, app);
} else {
  httpServer = http.createServer(app);
}
const server = httpServer.listen(process.env.PORT, process.env.HOSTNAME, function() {
  const host = server.address().address;
  const port = server.address().port;

  console.log('Server is listening at http://%s:%s', host, port);
});