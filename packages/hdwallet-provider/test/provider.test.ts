import assert from "assert";
// @ts-ignore
import Ganache from "ganache";
import * as EthUtil from "ethereumjs-util";
import Web3 from "web3";
import HDWalletProvider from "..";
import { describe, it, before, after, afterEach } from "mocha";

import { QtumJsonRpcProvider, computeAddress } from "qtum-ethers-wrapper";
// @ts-ignore
import ProviderSubprovider from "web3-provider-engine/subproviders/provider";

describe("HD Wallet Provider", function () {
  const web3 = new Web3();
  let ganacheProvider: any;
  let provider: HDWalletProvider;

  /*
  before(() => {
    ganacheProvider = Ganache.provider({
      miner: {
        instamine: "strict"
      },
      logging: {
        quiet: true
      }
    });
  });
  */

  before(() => {
    ganacheProvider = "http://localhost:23889";
    // ganacheProvider = new QtumJsonRpcProvider("http://localhost:23889");
  });

  after(async () => {
    /*
    await ganacheProvider.disconnect();
    */
  });

  afterEach(() => {
    web3.setProvider(null);
    if (provider) {
      provider.engine.stop();
    }
  });

  describe("instantiating with positional arguments", () => {
    it("provides for a mnemonic", async () => {
      const truffleDevAccounts = [
        "0xd11311e7957a316f858e71fc57f6fdf4a4bf6393",
        "0x38c3a6c3ae426c525d528203f715b047748fadf7",
        "0x5f3bb22fc543bd10b9a5c11a80ceace7812afae9",
        "0x465e57219287165ea76c3c7dc22e160729879a44",
        "0x80fd139b577ee551a80849725ea2dceb65cb2554",
        "0x54e9c688d242e196a23d6858541af9d88a7ca7ed",
        "0xabe9e3e042fddfab07ed6cc2c280d50f0da62b19",
        "0xb11b46155427de998271ebf178dfb67b81c21553",
        "0x3005c6cec3e90760ce788377bc5ff72b5be90f4f",
        "0xfcaa107d311590547e70c7587c1095f4d1502c48"
        /*
        "0x627306090abab3a6e1400e9345bc60c78a8bef57",
        "0xf17f52151ebef6c7334fad080c5704d77216b732",
        "0xc5fdf4076b8f3a5357c5e395ab970b5b54098fef",
        "0x821aea9a577a9b44299b9c15c88cf3087f3b5544",
        "0x0d1d4e623d10f9fba5db95830f7d3839406c6af2",
        "0x2932b7a2355d6fecc4b5c0b6bd44cc31df247a2e",
        "0x2191ef87e392377ec08e7c08eb105ef5448eced5",
        "0x0f4f2ac550a1b4e2280d04c21cea7ebd822934b5",
        "0x6330a553fc93768f612722bb8c2ec78ac90b3bbc",
        "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        */
      ];

      const mnemonic =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider(mnemonic, ganacheProvider);

      assert.deepEqual(provider.getAddresses(), truffleDevAccounts);
      web3.setProvider(provider);

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    it("throws on invalid mnemonic", () => {
      try {
        provider = new HDWalletProvider(
          "takoyaki is delicious",
          "http://localhost:8545"
        );
        assert.fail("Should throw on invalid mnemonic");
      } catch (e) {
        assert(e.message.includes("Could not create addresses"));
      }
    });

    it("provides for an array of private keys", async () => {
      const privateKeys = [
        "3f841bf589fdf83a521e55d51afddc34fa65351161eead24f064855fc29c9580",
        "9549f39decea7b7504e15572b2c6a72766df0281cea22bd1a3bc87166b1ca290"
      ];

      const privateKeysByAddress: { [address: string]: string } = {
        "0xc923875b0edca17821f970950f2a92b040a7c800":
          /*
        "0xc515db5834d8f110eee96c3036854dbf1d87de2b":
        */
          "3f841bf589fdf83a521e55d51afddc34fa65351161eead24f064855fc29c9580",
        "0x627b73d735d052b847df3a3623cd1ef1da1c050d":
          /*
        "0xbd3366a0e5d2fb52691e3e08fabe136b0d4e5929":
        */
          "9549f39decea7b7504e15572b2c6a72766df0281cea22bd1a3bc87166b1ca290"
      };

      provider = new HDWalletProvider(privateKeys, ganacheProvider);
      web3.setProvider(provider);

      const addresses = provider.getAddresses();
      assert.equal(
        addresses.length,
        privateKeys.length,
        "incorrect number of wallets derived"
      );
      addresses.forEach(address => {
        assert(EthUtil.isValidAddress(address), "invalid address");
        const privateKey = Buffer.from(privateKeysByAddress[address], "hex");
        const expectedAddress = `${computeAddress(
          /*
        const expectedAddress = `0x${EthUtil.privateToAddress(
        */
          privateKey,
          /*
        ).toString("hex")}`;
        */
          true
        ).toLowerCase()}`;
        assert.equal(
          address,
          expectedAddress,
          "incorrect address for private key"
        );
      });

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    it("provides for a private key", async () => {
      const privateKey =
        "3f841bf589fdf83a521e55d51afddc34fa65351161eead24f064855fc29c9580"; //random valid private key generated with ethkey
      provider = new HDWalletProvider(privateKey, ganacheProvider);
      web3.setProvider(provider);

      const addresses = provider.getAddresses();
      assert.equal(addresses[0], "0xc923875b0edca17821f970950f2a92b040a7c800");
      /*
      assert.equal(addresses[0], "0xc515db5834d8f110eee96c3036854dbf1d87de2b");
      */
      addresses.forEach(address => {
        assert(EthUtil.isValidAddress(address), "invalid address");
      });

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });
  });

  describe("instantiating with non-positional arguments", () => {
    it("provides for a mnemonic passed as an object", async () => {
      const truffleDevAccounts = [
        "0xd11311e7957a316f858e71fc57f6fdf4a4bf6393",
        "0x38c3a6c3ae426c525d528203f715b047748fadf7",
        "0x5f3bb22fc543bd10b9a5c11a80ceace7812afae9",
        "0x465e57219287165ea76c3c7dc22e160729879a44",
        "0x80fd139b577ee551a80849725ea2dceb65cb2554",
        "0x54e9c688d242e196a23d6858541af9d88a7ca7ed",
        "0xabe9e3e042fddfab07ed6cc2c280d50f0da62b19",
        "0xb11b46155427de998271ebf178dfb67b81c21553",
        "0x3005c6cec3e90760ce788377bc5ff72b5be90f4f",
        "0xfcaa107d311590547e70c7587c1095f4d1502c48"
        /*
        "0x627306090abab3a6e1400e9345bc60c78a8bef57",
        "0xf17f52151ebef6c7334fad080c5704d77216b732",
        "0xc5fdf4076b8f3a5357c5e395ab970b5b54098fef",
        "0x821aea9a577a9b44299b9c15c88cf3087f3b5544",
        "0x0d1d4e623d10f9fba5db95830f7d3839406c6af2",
        "0x2932b7a2355d6fecc4b5c0b6bd44cc31df247a2e",
        "0x2191ef87e392377ec08e7c08eb105ef5448eced5",
        "0x0f4f2ac550a1b4e2280d04c21cea7ebd822934b5",
        "0x6330a553fc93768f612722bb8c2ec78ac90b3bbc",
        "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        */
      ];

      const mnemonicPhrase =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider({
        mnemonic: {
          phrase: mnemonicPhrase
        },
        provider: ganacheProvider
      });

      assert.deepEqual(provider.getAddresses(), truffleDevAccounts);
      web3.setProvider(provider);

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    it("provides for a mnemonic passed as a string", async () => {
      const truffleDevAccounts = [
        "0xd11311e7957a316f858e71fc57f6fdf4a4bf6393",
        "0x38c3a6c3ae426c525d528203f715b047748fadf7",
        "0x5f3bb22fc543bd10b9a5c11a80ceace7812afae9",
        "0x465e57219287165ea76c3c7dc22e160729879a44",
        "0x80fd139b577ee551a80849725ea2dceb65cb2554",
        "0x54e9c688d242e196a23d6858541af9d88a7ca7ed",
        "0xabe9e3e042fddfab07ed6cc2c280d50f0da62b19",
        "0xb11b46155427de998271ebf178dfb67b81c21553",
        "0x3005c6cec3e90760ce788377bc5ff72b5be90f4f",
        "0xfcaa107d311590547e70c7587c1095f4d1502c48"
        /*
        "0x627306090abab3a6e1400e9345bc60c78a8bef57",
        "0xf17f52151ebef6c7334fad080c5704d77216b732",
        "0xc5fdf4076b8f3a5357c5e395ab970b5b54098fef",
        "0x821aea9a577a9b44299b9c15c88cf3087f3b5544",
        "0x0d1d4e623d10f9fba5db95830f7d3839406c6af2",
        "0x2932b7a2355d6fecc4b5c0b6bd44cc31df247a2e",
        "0x2191ef87e392377ec08e7c08eb105ef5448eced5",
        "0x0f4f2ac550a1b4e2280d04c21cea7ebd822934b5",
        "0x6330a553fc93768f612722bb8c2ec78ac90b3bbc",
        "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        */
      ];

      const mnemonicPhrase =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider({
        mnemonic: mnemonicPhrase,
        provider: ganacheProvider
      });

      assert.deepEqual(provider.getAddresses(), truffleDevAccounts);
      web3.setProvider(provider);

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    it("provides for a mnemonic with a password", async () => {
      const accounts = [
        "0x83aea4909c72e90b3399269ea157cba1137b0a4e",
        "0x0db58474f979e60a1d4e0731a9a6f6fb8cfa47d6",
        "0xc135c3b7e721a89da1c0579ec9165174698545d8",
        "0x4d92bd7250982d4173e0110f1b24081c2c5b3b35",
        "0x5afb3e6ca837dea794d25c50aa7b48c7be0d10f3",
        "0xae6d50a8a39c40e52d9a1f6e92e720ab852edae2",
        "0x3b907c0642d360b66c36c781ec81aa729c598727",
        "0xdeec8271a677adde8768f25f4e1579d40e8e1578",
        "0xd346f8e99746fe2c5da69c1ee7457a1c7cd048f0",
        "0xa3d081885769420bae20f78ec0c7dcab0ad867c5"
        /*
        "0x01d4195e36a244ceb6d6e2e55de1c406bf6089a0",
        "0x7e8f0f01542d14c1bfb9f07957ff61cade44abf3",
        "0x0d016902df6e479e766d7e1fb33efea4b779ac75",
        "0x7916ae4fdfe95a0487bb8742e73a2c44c7118702",
        "0x3bc32e23620a567d3cd2b41cc16c869f9923737e",
        "0x2b91922e2c17010bdae3ebfdb1fd608faae5c56a",
        "0xebc846a7ac330add2fc2ae8ea7cb1e76bad9447c",
        "0xcd7cbdef0dd539bfad28d995679575f0cebc940c",
        "0x11f1a3fa0e5c70fe6538aeb020ecca0faf6f7f70",
        "0x0a0d53ca0a996bf6bb4994514c3b6eb0c2b45e24"
        */
      ];
      const mnemonicPhrase =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider({
        mnemonic: {
          phrase: mnemonicPhrase,
          password: "yummy"
        },
        provider: ganacheProvider
      });

      assert.deepEqual(provider.getAddresses(), accounts);
      web3.setProvider(provider);

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    it("provides for a default polling interval", () => {
      const mnemonicPhrase =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider({
        mnemonic: {
          phrase: mnemonicPhrase
        },
        provider: ganacheProvider
        // polling interval is unspecified
      });
      assert.ok(provider.engine, "Web3ProviderEngine instantiated");
      assert.ok(
        (provider.engine as any)._blockTracker,
        "PollingBlockTracker instantiated"
      );
      assert.deepEqual(
        (provider.engine as any)._blockTracker._pollingInterval,
        4000,
        "PollingBlockTracker with expected pollingInterval"
      );
    });

    it("provides for a custom polling interval", () => {
      const mnemonicPhrase =
        "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat";
      provider = new HDWalletProvider({
        mnemonic: {
          phrase: mnemonicPhrase
        },
        provider: ganacheProvider,
        // double the default value, for less chatty JSON-RPC
        pollingInterval: 8000
      });
      assert.ok(provider.engine, "Web3ProviderEngine instantiated");
      assert.ok(
        (provider.engine as any)._blockTracker,
        "PollingBlockTracker instantiated"
      );
      assert.deepEqual(
        (provider.engine as any)._blockTracker._pollingInterval,
        8000,
        "PollingBlockTracker with expected pollingInterval"
      );
    });

    it("provides for an array of private keys", async () => {
      const privateKeys = [
        "3f841bf589fdf83a521e55d51afddc34fa65351161eead24f064855fc29c9580",
        "9549f39decea7b7504e15572b2c6a72766df0281cea22bd1a3bc87166b1ca290"
      ];

      const privateKeysByAddress: { [address: string]: string } = {
        "0xc923875b0edca17821f970950f2a92b040a7c800":
          /*
        "0xc515db5834d8f110eee96c3036854dbf1d87de2b":
        */
          "3f841bf589fdf83a521e55d51afddc34fa65351161eead24f064855fc29c9580",
        "0x627b73d735d052b847df3a3623cd1ef1da1c050d":
          /*
        "0xbd3366a0e5d2fb52691e3e08fabe136b0d4e5929":
        */
          "9549f39decea7b7504e15572b2c6a72766df0281cea22bd1a3bc87166b1ca290"
      };

      provider = new HDWalletProvider({
        privateKeys,
        provider: ganacheProvider
      });
      web3.setProvider(provider);

      const addresses = provider.getAddresses();
      assert.equal(
        addresses.length,
        privateKeys.length,
        "incorrect number of wallets derived"
      );
      addresses.forEach(address => {
        assert(EthUtil.isValidAddress(address), "invalid address");
        const privateKey = Buffer.from(privateKeysByAddress[address], "hex");
        const expectedAddress = `${computeAddress(
          /*
        const expectedAddress = `0x${EthUtil.privateToAddress(
        */
          privateKey,
          /*
        ).toString("hex")}`;
        */
          true
        ).toLowerCase()}`;
        assert.equal(
          address,
          expectedAddress,
          "incorrect address for private key"
        );
      });

      /*
      const number = await web3.eth.getBlockNumber();
      assert(number === 0);
      */
    });

    describe("instantiation errors", () => {
      it("throws on invalid providers", () => {
        try {
          provider = new HDWalletProvider({
            mnemonic: {
              phrase:
                "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat"
            },
            // @ts-ignore we gotta do the bad thing here to get the test right
            provider: { junk: "in", an: "object" }
          });
          assert.fail("Should throw on invalid provider");
        } catch (e) {
          assert(e.message.includes("invalid provider was specified"));
        }
      });

      it("throws on invalid urls", () => {
        try {
          provider = new HDWalletProvider({
            mnemonic: {
              phrase:
                "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat"
            },
            url: "justABunchOfJunk"
          });
          assert.fail("Should throw on invalid url");
        } catch (e) {
          assert(e.message.includes("invalid provider was specified"));
        }
      });

      it("throws on invalid mnemonic", () => {
        try {
          provider = new HDWalletProvider({
            mnemonic: {
              phrase: "I am not a crook"
            },
            url: "http://localhost:8545"
          });
          assert.fail("Should throw on invalid mnemonic");
        } catch (e) {
          assert(e.message.includes("Mnemonic invalid or undefined"));
        }
      });
    });
  });
});
