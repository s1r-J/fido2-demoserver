import crypto from 'crypto';
import axios from 'axios';
import base64url from 'base64url';
import FidoMds3 from "fido-mds3";

const NOT_ALLOWED_STATUS = [
  'NOT_FIDO_CERTIFIED',
  'USER_VERIFICATION_BYPASS',
  'ATTESTATION_KEY_COMPROMISE',
  'USER_KEY_REMOTE_COMPROMISE',
  'SER_KEY_PHYSICAL_COMPROMISE',
  'REVOKED',
];

class MdsUtil {

  _entries;
  _client;

  constructor(addonEntries) {
    this._entries = addonEntries || [];
    const builder = new FidoMds3.Builder();
    this._client = builder.build();
  }

  async findEntry(aaguid) {
    let entry = this._entries.find(e => e.aaguid === aaguid);
    if (entry != null) {
      return entry;
    }

    entry = await this._client.findByAAGUID(aaguid);
    return entry;
  }

  async verifyEntry(entry, mdsAlg, attestationTypes) {
    if (entry == null) {
      throw new Error('Metadata entry is null or undefined.');
    }

    const statusReports = entry.statusReports;
    if (statusReports != null && statusReports.length !== 0) {
      if (NOT_ALLOWED_STATUS.includes(statusReports[0].status)) {
        throw new Error('Authenticator status is invalid: ' + statusReports[0].status);
      }
    }

    if (entry.attestationTypes != null && entry.attestationTypes.length !== 0) {
      const entryATs = entry.attestationTypes.map(at => {
        switch (at) {
          case 15879:
            return 'basic_full';
          case 15880:
            return 'basic_surrogate';
          case 15881:
            return 'ecdaa';
          case 15882:
            return 'attca';
          default:
            return at;
        }
      });
      const isValidAttestationType = entryATs.some(eat => {
        return attestationTypes.some(at => {
          switch (at) {
            case 'Basic':
            case 'AttCA':
            case 'AnonCA':
                return eat === 'basic_full' || eat === 'anonca' || eat === 'attca';
            case 'Self':
              return eat === 'basic_surrogate';
            default:
              return true;
          }
        });
      });
      if (!isValidAttestationType) {
        throw new Error(`Attestation type does not match. Expect: ${entryATs.join(',')} Actual: ${attestationTypes.join(', ')}`);
      }
    }
    if (entry.hash != null && entry.url != null) {
      const hashAlg = mdsAlg || 'sha256';
      const res = await axios.get(entry.url);
      const hash = base64url.fromBase64(crypto.createHash(hashAlg).update(res.data).digest('base64'));
      if (entry.hash !== hash) {
        throw new Error('hash does not match.');
      }
    }

  }
}

export default MdsUtil;
