/*
 * Copyright 2019 Rabobank NL
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

import {
  IProofParams,
  IVerifiablePresentationParams,
  Proof,
  VerifiableCredential,
  VerifiablePresentation
} from 'vp-toolkit-models'
import { CryptUtil } from 'crypt-util'
import { v4 as uuid } from 'uuid'
import { VerifiableCredentialSigner } from './verifiable-credential-signer'
import { keccak256 } from 'js-sha3'

export class VerifiablePresentationSigner {

  constructor (private _cryptUtil: CryptUtil, private _verifiableCredentialSigner: VerifiableCredentialSigner) {
  }

  get signatureType () {
    return this._cryptUtil.algorithmName + 'Signature2019'
  }

  get cryptUtil () {
    return this._cryptUtil
  }

  /**
   * Creates a proof objects for the VerifiableCredentials.
   * Because CryptUtil is being used, we need to provide an
   * accountId and keyId so the VC is signed with
   * the correct derivated key. If you use only one global
   * key for your product, then provide the accountId and
   * keyId once.
   *
   * A random uuid will be used if the correspondenceId
   * is not provided.
   *
   * @param vp the verifiable presentation parameters (not the object itself)
   * @param {{accountId: number, keyId: number}[]} keys
   * @param {string} correspondenceId to use as proof nonce to prove the session between holder and counterparty
   * @return IProofParams[]
   */
  public generateProofs (vp: IVerifiablePresentationParams, keys: { accountId: number, keyId: number }[], correspondenceId?: string): IProofParams[] {
    const proofs: IProofParams[] = []
    for (const vc of vp.verifiableCredential) {
      for (const keySet of keys) {
        const address = this._cryptUtil.deriveAddress(keySet.accountId, keySet.keyId)
        // The if statement checks if this keyset can prove the ownership over this VC in two ways
        if (!vc.issuer.endsWith(address) // Cannot prove this as a self attested VC
          && (!vc.credentialSubject.id || !vc.credentialSubject.id.endsWith(address))) { // Also not as a third-party VC
          continue // Go to the next keyset
        }

        // Apparently we can use this keyset to prove ownership over this VC
        const nonce = correspondenceId || uuid() // If the correspondenceId was not provided, a random uuid will be used
        const date = new Date()
        const payload = JSON.stringify(vc) + nonce + date.toISOString()
        const sigValue = this._cryptUtil.signPayload(keySet.accountId, keySet.keyId, payload)
        const pubKey = this._cryptUtil.derivePublicKey(keySet.accountId, keySet.keyId)
        proofs.push({
          type: this.signatureType,
          created: date,
          verificationMethod: pubKey,
          nonce: nonce,
          signatureValue: sigValue
        })
      }
    }

    return proofs
  }

  /**
   * Verifies all VerifiableCredential
   * signatures.
   *
   * Optionally verifies the
   * ownership signatures from the
   * VerifiablePresentation.
   *
   * Only proof sets are supported.
   * @see https://w3c-dvcg.github.io/ld-proofs/#proof-sets
   *
   * @param {VerifiablePresentation} model
   * @param {string|undefined} correspondenceId this string must be included in the VP proof if ownership is validated
   * @param {boolean} skipOwnershipValidation
   * @return boolean
   */
  public verifyVerifiablePresentation (model: VerifiablePresentation, skipOwnershipValidation = false, correspondenceId?: string): boolean {

    const proofsCopy = [...model.proof]

    for (const vc of model.verifiableCredential) {
      if (!this._verifiableCredentialSigner.verifyVerifiableCredential(vc)) {
        return false
      }

      if (skipOwnershipValidation) {
        continue
      }
      const matchProof = this.matchAndRemove(proofsCopy, vc)
      if (matchProof === null) {
        return false
      }

      // Check credential ownership by looping through the VP proofs and find the matching proof
      let ownershipIsValid = false
      const ownershipSignature = matchProof.signatureValue as string
      const payloadToVerifiy = JSON.stringify(vc) + matchProof.nonce + matchProof.created
      if (this._cryptUtil.verifyPayload(payloadToVerifiy, matchProof.verificationMethod, ownershipSignature)
        && (correspondenceId === undefined || matchProof.nonce === correspondenceId)) {
        ownershipIsValid = true
        break
      }

      if (!ownershipIsValid) {
        return false
      }
    }
    if (!skipOwnershipValidation && (proofsCopy.length !== 0)) {
      return false
    }
    return true
  }

  private matchAndRemove (proofs: Proof[], vc: VerifiableCredential): Proof | null {
    const credentialDid = vc.credentialSubject.id
    const index = proofs.map(p => {
      return 'did:eth:' + this.toChecksumAddress(keccak256(Buffer.from(p.verificationMethod, 'hex')).slice(-40))
    }).indexOf(credentialDid)
    return index === -1 ? null : proofs.splice(index, 1)[0]
  }

  private toChecksumAddress (address: string): string {
    const hash = keccak256(address)
    let ret = '0x'
    for (let i = 0; i < address.length; i++) {
      if (parseInt(hash[i], 16) >= 8) {
        ret += address[i].toUpperCase()
      } else {
        ret += address[i]
      }
    }
    return ret
  }
}
