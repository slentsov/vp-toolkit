"use strict";
/*
 * Copyright 2019 Coöperatieve Rabobank U.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
Object.defineProperty(exports, "__esModule", { value: true });
const vp_toolkit_models_1 = require("vp-toolkit-models");
const js_sha3_1 = require("js-sha3");
class VerifiableCredentialSigner {
    constructor(_cryptUtil) {
        this._cryptUtil = _cryptUtil;
    }
    get signatureType() {
        return this._cryptUtil.algorithmName + 'Signature2019';
    }
    get cryptUtil() {
        return this._cryptUtil;
    }
    /**
     * Signs the VerifiableCredential (VC) model and returns the SignatureValue.
     * Because CryptUtil is being used, we need to provide an
     * accountId and keyId so the VC is signed with
     * the correct derivated key. If you use only one key for
     * every sign action, use 0 for accountId and keyId.
     *
     * @param {VerifiableCredential} model
     * @param {number} accountId
     * @param {number} keyId
     * @return string
     */
    signVerifiableCredential(model, accountId, keyId) {
        const modelWithoutSignatureValue = new vp_toolkit_models_1.VerifiableCredential(model.toJSON()); // Copy to new variable
        modelWithoutSignatureValue.proof.signatureValue = undefined;
        return this._cryptUtil.signPayload(accountId, keyId, JSON.stringify(modelWithoutSignatureValue));
    }
    /**
     * Verifies the VerifiableCredential model and its SignatureValue.
     *
     * @param {VerifiableCredential} model
     * @return boolean
     */
    verifyVerifiableCredential(model) {
        const modelWithoutSignatureValue = new vp_toolkit_models_1.VerifiableCredential(model.toJSON()); // Copy to new variable
        const publicKey = model.proof.verificationMethod;
        const signature = model.proof.signatureValue;
        modelWithoutSignatureValue.proof.signatureValue = undefined; // Removed the SignatureValue because that field was also empty when signing the payload
        const issuerDid = 'did:eth:0x' + js_sha3_1.keccak256(Buffer.from(publicKey, 'hex')).slice(-40);
        const payload = JSON.stringify(modelWithoutSignatureValue);
        return issuerDid === model.issuer && this._cryptUtil.verifyPayload(payload, publicKey, signature);
    }
}
exports.VerifiableCredentialSigner = VerifiableCredentialSigner;
//# sourceMappingURL=verifiable-credential-signer.js.map