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

import * as chai from 'chai'
import { ChallengeRequest, IProofParams } from 'vp-toolkit-models'
import { LocalCryptUtils } from 'crypt-util'
import { ChallengeRequestSigner } from '../../src'

const assert = chai.assert

const privKey = 'xprv9s21ZrQH143K3T7143BKMvxoLpFzUkoyU7sQS7iQ88FVGatVTvFe1sKU1Vvysj378AAvvTyjziPZ6AisTNV7uC9irDHEnxZqGYpeceP1S6c'
const accountId = 0
const keyId = 0
const derivedPubKey = '58ffea3c24293e9939823b165a7e9c565077e2458e823a396bdcafa65a4b1e768463a4a80aaa76c15848a4c9c16ff19361ef529cd7b890748fc717a82afe6aae' // From privKey, accountId and keyId
const testProof: IProofParams = {
  type: 'Secp256k1Signature2019',
  created: new Date(Date.UTC(2019, 0, 1, 23, 34, 56)),
  verificationMethod: derivedPubKey,
  nonce: '50d2df25-b223-4bed-b9f5-3f16ea299fa1'
}
const challengeRequest = new ChallengeRequest({
  toAttest: [{ predicate: 'https://schema.org/familyName' }],
  toVerify: [{ predicate: 'https://schema.org/initials' }],
  postEndpoint: 'https://endpoint.com/something',
  proof: testProof,
  correspondenceId: '21a7133d-861b-4e30-aa52-14c21cc51ecc'
})

before(() => {
  chai.should()
})

describe('Integration: challenge request signer', function () {
  it('should sign a ChallengeRequest', () => {
    const cryptUtil = new LocalCryptUtils()
    cryptUtil.importMasterPrivateKey(privKey)
    const sut = new ChallengeRequestSigner(cryptUtil)
    const expectedSignature = '632cd48ec2951f423d32fefd9749d9495e09737b8dd6ee6224fb61353a7175da4f9e32a6f04e2e002ca570503d7ee37211d71edf431c4b230d87fe912e67dde7'

    const signature = sut.signChallengeRequest(challengeRequest, accountId, keyId)

    assert.equal(signature, expectedSignature)
  })

  it('should create, sign and validate ChallengeRequest properly', () => {
    const cryptUtil = new LocalCryptUtils()
    cryptUtil.importMasterPrivateKey(privKey)
    const sut = new ChallengeRequestSigner(cryptUtil)

    const crObject = new ChallengeRequest({
      toAttest: [{ predicate: 'https://schema.org/familyName' }],
      toVerify: [{ predicate: 'https://schema.org/initials' }],
      postEndpoint: 'https://endpoint.com/something',
      proof: {
        type: 'Secp256k1Signature2019',
        created: new Date('01-01-2019 12:34:00'),
        verificationMethod: derivedPubKey
      }
    })

    // First obtain and set the signature for the object
    crObject.proof.signatureValue = sut.signChallengeRequest(crObject, accountId, keyId)
    // Validate the signed object
    const isValid = sut.verifyChallengeRequest(crObject)

    assert.isTrue(isValid)
  })
})
