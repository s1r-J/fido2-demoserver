class RequestValidateUtil {

  static FIDO_SELECTION = ['required', 'preferred', 'discouraged'];

  static isString(str) {
    if (str == null) {
      return false;
    }
    return typeof str === 'string';
  }

  static isBlank(str) {
    if (str == null) {
      return true;
    }
    if (RequestValidateUtil.isString(str)) {
      return str.length === 0;
    }
  }

  static isBase64(str) {
    if (RequestValidateUtil.isBlank(str)) {
      return false;
    }
    if (!RequestValidateUtil.isString(str)) {
      return false;
    }
    const re = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    return re.test(str);
  }

  static isBase64url(str) {
    if (RequestValidateUtil.isBlank(str)) {
      return false;
    }
    if (!RequestValidateUtil.isString(str)) {
      return false;
    }
    const re = /^[A-Za-z0-9-_]*$/;
    return re.test(str);
  }

  static attestationOptions(req) {
    const {
      username,
      displayName,
      authenticatorSelection,
      attestation,
    } = req.body;
    if (RequestValidateUtil.isBlank(username) || !RequestValidateUtil.isString(username)) {
      throw new Error('username is invalid.');
    }
    if (RequestValidateUtil.isBlank(displayName) || !RequestValidateUtil.isString(displayName)) {
      throw new Error('displayName is invalid.');
    }
    if (authenticatorSelection != null) {
      if (!RequestValidateUtil.isBlank(authenticatorSelection.authenticatorAttachment) && !['cross-platform', 'platform'].includes(authenticatorSelection.authenticatorAttachment)) {
        throw new Error('authenticatorSelection.authenticatorAttachment is invalid.');
      }
      if (!RequestValidateUtil.isBlank(authenticatorSelection.userVerification) && !RequestValidateUtil.FIDO_SELECTION.includes(authenticatorSelection.userVerification)) {
        throw new Error('authenticatorSelection.userVerification is invalid.');
      }
      if (!RequestValidateUtil.isBlank(authenticatorSelection.requireResidentKey) && (typeof authenticatorSelection.requireResidentKey !== 'boolean')) {
        throw new Error('authenticatorSelection.requireResidentKey is invalid.');
      }
      if (!RequestValidateUtil.isBlank(authenticatorSelection.residentKey) && !RequestValidateUtil.FIDO_SELECTION.includes(authenticatorSelection.residentKey)) {
        throw new Error('authenticatorSelection.residentKey is invalid.');
      }
    }
    if (RequestValidateUtil.isBlank(attestation) || !['none', 'indirect', 'direct', 'enterprise'].includes(attestation)) {
      throw new Error('attestation is invalid.');
    }

    return true;
  }

  static attestationResult(req) {
    const {
      id,
      rawId,
      response,
      type,
    } = req.body;

    if (RequestValidateUtil.isBlank(id) || !RequestValidateUtil.isBase64url(id)) {
      throw new Error('id is invalid.');
    }
    if (response == null) {
      throw new Error('response is invalid.');
    }
    const {
      clientDataJSON,
      attestationObject,
    } = response;
    if (RequestValidateUtil.isBlank(clientDataJSON) || !RequestValidateUtil.isBase64url(clientDataJSON)) {
      throw new Error('clientDataJSON is invalid.');
    }
    if (RequestValidateUtil.isBlank(attestationObject) || !RequestValidateUtil.isBase64url(attestationObject)) {
      throw new Error('attestationObject is invalid.');
    }
    if (type !== 'public-key') {
      throw new Error('type is invalid.');
    }

    return true;
  }

  static assertionOptions(req) {

    const { username, userVerification } = req.body;
    if (RequestValidateUtil.isBlank(username) || !RequestValidateUtil.isString(username)) {
      throw new Error('username is invalid.');
    }
    if (!RequestValidateUtil.isBlank(userVerification) && !['required', 'preferred', 'discouraged'].includes(userVerification)) {
      throw new Error('userVerification is invalid.');
    }

    return true;
  }

  static assertionResult(req) {
    const {
      id,
      rawId,
      response,
      type,
    } = req.body;

    if (RequestValidateUtil.isBlank(id) || !RequestValidateUtil.isBase64url(id)) {
      throw new Error('id is invalid.');
    }
    if (response == null) {
      throw new Error('response is invalid.');
    }
    if (RequestValidateUtil.isBlank(response.authenticatorData) || !RequestValidateUtil.isBase64url(response.authenticatorData)) {
      throw new Error('response.authenticatorData is invalid.');
    }
    if (RequestValidateUtil.isBlank(response.signature) || !RequestValidateUtil.isBase64url(response.signature)) {
      throw new Error('response.signature is invalid.');
    }
    if (RequestValidateUtil.isBlank(response.clientDataJSON) || !RequestValidateUtil.isBase64url(response.clientDataJSON)) {
      throw new Error('response.clientDataJSON is invalid.');
    }
    if (!RequestValidateUtil.isBlank(response.userHandle) && !RequestValidateUtil.isBase64url(response.userHandle)) {
      throw new Error('response.userHandle is invalid.');
    }
    if (type !== 'public-key') {
      throw new Error('type is invalid.');
    }

    return true;
  }
}

export default RequestValidateUtil;
