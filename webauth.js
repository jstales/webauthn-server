import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
} from "@simplewebauthn/server";
import {} from "base64-arraybuffer";
import base64url from "base64url";
const RP_NAME = "JS Tales";
const TIMEOUT = 60 * 1000;

export function getRegistrationOptions(user) {
  try {
    const excludeCredentials = [];
    if (user.credentials.length) {
      for (let cred of user.credentials) {
        excludeCredentials.push({
          id: base64url.toBuffer(cred.credId),
          type: "public-key",
          transports: ["internal"],
        });
      }
    }

    const options = generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.id,
      userName: user.email,
      timeout: TIMEOUT,
      excludeCredentials,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    return options;
  } catch (e) {
    throw e;
  }
}

export function getLoginOptions(credId, user) {
  try {
    const matchedCredential = user.credentials.find(
      (cred) => cred.credId === credId
    );
    const allowCredentials = matchedCredential
      ? [
          {
            type: "public-key",
            transports: ["internal"],
            id: base64url.toBuffer(matchedCredential.credId),
          },
        ]
      : [];

    const options = generateAuthenticationOptions({
      timeout: TIMEOUT,
      rpID: process.env.HOSTNAME,
      allowCredentials,
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification: "required",
    });

    return options;
  } catch (e) {
    throw e;
  }
}
