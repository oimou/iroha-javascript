import * as axios from "axios";
import * as moment from "moment";

import { IKeyPair, supercop, sha3 } from "./irohajs";

/**
 * Inteface of iroha wallet.
 */
export interface IWallet {
  privateKey: Buffer;
  publicKey: Buffer;
}

/**
 * Iroha wallet.
 */
export class Wallet implements IWallet {
  privateKey: Buffer;
  publicKey: Buffer;

  constructor (keyPair?: IWallet) {
    const seed = supercop.createSeed();
    const keys = keyPair || supercop.createKeyPair(seed);

    this.publicKey = keys.publicKey;
    this.privateKey = (keyPair) ? keyPair.privateKey : keys.secretKey;
  }

  toJSON (): IKeyPair {
    return {
      publicKey: this.publicKey.toString("base64"),
      privateKey: this.privateKey.toString("base64")
    };
  }

  sign (msg: string): string {
    const message = new Buffer(sha3(msg, { outputLength: 256 }).toString());
    return supercop.sign(message, this.publicKey, this.privateKey).toString("base64");
  }
}
