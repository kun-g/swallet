const { pbkdf2Sync } = require('crypto');
const { randomBytes, secretbox } = require('tweetnacl');
const bip39 = require('bip39');
const bs58 = require('bs58');
const { Keypair, Connection, Transaction } = require('@solana/web3.js');
const { Token, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, AccountLayout } = require('@solana/spl-token');
const { derivePath } = require('ed25519-hd-key');
const { readFileSync, writeFileSync } = require('fs')

class Wallet {
    static fromPrivateKey (privateKey) {
        return new Wallet({ privateKey })
    }

    static fromMnemonic (mnemonic, accountIndex) {
        return new Wallet({ mnemonic, accountIndex })
    }

    static generateMnemonic () {
        return new Wallet({ mnemonic: bip39.generateMnemonic(256) })
    }

    constructor (args) {
        if (args.privateKey) {
            this.keypair = Keypair.fromSecretKey(args.secretKey)
        } else if (args.mnemonic) {
            this.mnemonic = args.mnemonic
            if (!bip39.validateMnemonic(this.mnemonic)) {
                throw new Error('Invalid seed words');
            }
            this._seed = bip39.mnemonicToSeedSync(this.mnemonic)
            this.setAccountIndex(args.accountIndex || 0)
        }
    }

    setAccountIndex (index) {
        this.accountIndex = index
        this.keypair = getAccountFromSeed(this._seed, this.accountIndex)
        this.publicKey = this.keypair.publicKey
        this.privateKey = this.keypair.privateKey
    }

    nextAccount () {
        this.setAccountIndex(this.accountIndex + 1)
        return this.keypair
    }

    get seed () {
        return Buffer.from(this._seed).toString('hex')
    }

    get address () {
        return this.publicKey.toBase58()
    }

    get connection () {
        if (this._connection == null) {
            this._connection = new Connection('https://solana-mainnet.phantom.tech/');
        }
        return this._connection
    }

    getBalance = async function () {
        return await this.connection.getBalance(this.publicKey)
    }

    getTokenAccounts = async function (force = false) {
        if (this.tokenAccounts == null || force) {
            this.tokenAccounts = await getTokenAccountsByOwner(this.connection, this.publicKey)
        }

        return this.tokenAccounts
    }

    getTokenAccount = async function (mintAddress, force=false) {
        for (let a of await this.getTokenAccounts(force)) {
            if (a.mint == mintAddress) {
                return a
            }
        }
        return null
    }

    signTransaction = async (transaction) => {
        transaction.partialSign(this.keypair);
        return transaction;
    };

    // TODO 签名 & 验签
    createSignature (message) {
        return bs58.encode(nacl.sign.detached(message, this.privateKey));
    };

    save (path, password) {
        let text = storeMnemonicAndSeed(this.mnemonic, password)
        writeFileSync(path, text)
    }

    static load (path, password) {
        return new Wallet(loadMnemonicAndSeed(readFileSync(path), password))
    }
}

async function getTokenAccountsByOwner (conn, publicKey) {
    let res = await conn.getParsedTokenAccountsByOwner(publicKey, { programId: TOKEN_PROGRAM_ID })
    return res.value.reduce((r, acc) => {
        let { account, pubkey } = acc
        let { mint, tokenAmount } = account.data.parsed.info
        if (r[mint]) {
            console.log("Duplicate Account", mint, tokenAmount, pubkey.toBase58())
            console.log(r[mint])
        }

        r[mint] = {
            mint,
            pubkey,
            amount: tokenAmount
        }
        return r
    }, {})
}

function getAccountFromSeed(seed, walletIndex) {
    const path44Change = `m/44'/501'/${walletIndex}'/0'`;
    const derivedSeed = derivePath(path44Change, seed).key;
    return Keypair.fromSeed(derivedSeed);
}

function storeMnemonicAndSeed(mnemonic, password) {
    let plaintext = JSON.stringify({ mnemonic });
    if (password) {
        const salt = randomBytes(16);
        const kdf = 'pbkdf2';
        const iterations = 100000;
        const digest = 'sha256';
        const key = deriveEncryptionKey(password, salt, iterations, digest);
        const nonce = randomBytes(secretbox.nonceLength);
        const encrypted = secretbox(Buffer.from(plaintext), nonce, key);
        plaintext = JSON.stringify({
            encrypted: bs58.encode(encrypted),
            nonce: bs58.encode(nonce),
            kdf,
            salt: bs58.encode(salt),
            iterations,
            digest,
        })
    }
    return plaintext
}

function loadMnemonicAndSeed(text, password) {
    let {
        encrypted: encodedEncrypted,
        mnemonic,
        nonce: encodedNonce,
        salt: encodedSalt,
        iterations,
        digest,
    } = JSON.parse(text);

    if (password) {
        const encrypted = bs58.decode(encodedEncrypted);
        const nonce = bs58.decode(encodedNonce);
        const salt = bs58.decode(encodedSalt);
        const key = deriveEncryptionKey(password, salt, iterations, digest);
        const plaintext = secretbox.open(encrypted, nonce, key);
        if (!plaintext) {
            throw new Error('Incorrect password');
        }
        const decodedPlaintext = Buffer.from(plaintext).toString();
        mnemonic = JSON.parse(decodedPlaintext).mnemonic
    }

    return { mnemonic }
}

function deriveEncryptionKey(password, salt, iterations, digest) {
    return pbkdf2Sync(password, salt, iterations, secretbox.keyLength, digest)
}

async function getTokenAccountsByOwner (conn, publicKey) {
    let res = await conn.getParsedTokenAccountsByOwner(publicKey, { programId: TOKEN_PROGRAM_ID })
    return res.value.map(e => {
        let { account, pubkey } = e
        let { mint, tokenAmount } = account.data.parsed.info
        return {
            mint: mint,
            pubkey: pubkey,
            amount: tokenAmount.uiAmount,
            decimals: tokenAmount.decimals
        }
    })
}

async function migrateDuplicateTokenAccounts (wallet) {
    let accounts = {}

    for (let a of await wallet.getTokenAccounts()) {
        if (accounts[a.mint] == null) {
            accounts[a.mint] = []
        }

        accounts[a.mint].push(a)
    }

    let transaction = new Transaction({ payer: wallet.publicKey })
    for (let m in accounts) {
        if (accounts[m].length  == 1) {
            continue
        }

        for (let i = 0; i < accounts[m].length; i++) {
            if (accounts[m][i].amount == 0) {
                transaction.add(Token.createCloseAccountInstruction(TOKEN_PROGRAM_ID, accounts[m][i].pubkey, wallet.publicKey, wallet.publicKey,[wallet.keypair]))
            }
        }
        if (transaction.instructions.length == accounts[m].length) {
            transaction.instructions.pop()
        }
    }

    if (transaction.instructions.length) {
        return await wallet.connection.sendTransaction(transaction, [wallet.keypair])
    } else {
        return null
    }
}

module.exports.Wallet = Wallet
module.exports.migrateDuplicateTokenAccounts = migrateDuplicateTokenAccounts
