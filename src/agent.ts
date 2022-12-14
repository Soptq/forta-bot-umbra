import {
  BlockEvent,
  Finding,
  HandleBlock,
  HandleTransaction,
  TransactionEvent,
  FindingSeverity,
  FindingType, ethers,
} from "forta-agent";
import { handlers, createAddress } from "forta-agent-tools";

// When Umbra is updated, the following 5 variables are probably the only variables that need to be changed accordingly.
const umbraContract = createAddress("0xFb2dc580Eed955B528407b4d36FfaFe3da685401");
const sendETHFunctionHash = "0xbeb9addf";
const sendTokensFunctionHash = "0xb9bfabe1";
const withdrawTokensOnBehalfHash = "0x81ab0fcd";
const umbraCache: any = {}

const erc20TransfersHandler = new handlers.Erc20Transfers({
  onFinding(metadata) {
    return Finding.from({
      name: "ERC20 transfer",
      description: "A ERC20 transfer was detected",
      alertId: "FORTA-1",
      severity: FindingSeverity.Info,
      type: FindingType.Info,
      metadata: {
        token: metadata.emitter,
        from: metadata.from,
        to: metadata.to,
        amount: metadata.amount.toString(),
      },
    });
  },
});

const ethTransfersHandler = new handlers.EthTransfers({
  onFinding(metadata) {
    return Finding.from({
      name: "Ether transfer",
      description: "A ether transfer was detected",
      alertId: "FORTA-1",
      severity: FindingSeverity.Info,
      type: FindingType.Info,
      metadata: {
        from: metadata.from,
        to: metadata.to,
        value: metadata.value.toString(),
      },
    });
  },
});

const detectsUmbraWithdraw = async (
  txEvent: TransactionEvent,
  stealthAddress: string,
  sponsor: string = "0x0000000000000000000000000000000000000000"
) => {
  if (!txEvent.transaction.to) {
    return [];
  }

  const findings = [];
  const networkNumber = txEvent.network as number;

  const fromAddress = createAddress(txEvent.transaction.from);
  const value = ethers.BigNumber.from(txEvent.transaction.value);
  const calldata = txEvent.transaction.data;
  const funcHash = calldata.slice(0, 10).toLowerCase();
  // detect funds receiving from stealth address
  if (networkNumber in umbraCache && stealthAddress in umbraCache[networkNumber]) {
    const tokenReceived: any = {};
    if (value.gt(0)) {
      const toAddress = createAddress(txEvent.transaction.to);
      const gasFee = ethers.BigNumber.from(txEvent.transaction.gasPrice).mul(txEvent.transaction.gas);
      tokenReceived[createAddress("0x0")] = {};
      tokenReceived[createAddress("0x0")][toAddress] = value.add(gasFee);
    }

    const eth_transfer_findings = await ethTransfersHandler.handle(txEvent);
    for (const finding of eth_transfer_findings) {
      const ethFromAddress = createAddress(finding.metadata.from);
      const ethToAddress = createAddress(txEvent.transaction.to);
      const ethAmount = ethers.BigNumber.from(finding.metadata.value);
      if (ethFromAddress === (funcHash === withdrawTokensOnBehalfHash ? umbraContract : fromAddress)) {
        if (createAddress("0x0") in tokenReceived) {
          if (ethToAddress in tokenReceived[createAddress("0x0")]) {
            tokenReceived[createAddress("0x0")][ethToAddress] = tokenReceived[createAddress("0x0")][ethToAddress].add(ethAmount);
          } else {
            tokenReceived[createAddress("0x0")][ethToAddress] = ethAmount;
          }
        } else {
          tokenReceived[createAddress("0x0")] = {};
          tokenReceived[createAddress("0x0")][ethToAddress] = ethAmount;
        }
      }
    }

    const erc20_transfer_findings = await erc20TransfersHandler.handle(txEvent);
    let toAddress = createAddress("0x0");
    for (const finding of erc20_transfer_findings) {
      const erc20ToAddress = createAddress(txEvent.transaction.to);
      if (erc20ToAddress !== sponsor) toAddress = erc20ToAddress;
    }
    for (const finding of erc20_transfer_findings) {
      const erc20TokenAddress = createAddress(finding.metadata.token);
      const erc20FromAddress = createAddress(finding.metadata.from);
      const erc20Amount = ethers.BigNumber.from(finding.metadata.amount);
      if (erc20FromAddress === (funcHash === withdrawTokensOnBehalfHash ? umbraContract : fromAddress)) {
        if (erc20TokenAddress in tokenReceived) {
          if (toAddress in tokenReceived[erc20TokenAddress]) {
            tokenReceived[erc20TokenAddress][toAddress] = tokenReceived[erc20TokenAddress][toAddress].add(erc20Amount);
          } else {
            tokenReceived[erc20TokenAddress][toAddress] = erc20Amount;
          }
        } else {
          tokenReceived[erc20TokenAddress] = {};
          tokenReceived[erc20TokenAddress][toAddress] = erc20Amount;
        }
      }
    }

    for (const [tokenAddress, data] of Object.entries(tokenReceived)) {
      // @ts-ignore
      for (const [toAddress, amount] of Object.entries(data)) {
        if (!(tokenAddress in umbraCache[networkNumber][stealthAddress])) {
          continue;
        }

        const stealthData = umbraCache[networkNumber][stealthAddress][tokenAddress];

        findings.push(
          Finding.fromObject({
            name: "Umbra Receive Detected",
            description: "Umbra Receive Detected",
            alertId: "UMBRA-RECEIVE",
            severity: FindingSeverity.Info,
            type: FindingType.Info,
            metadata: {
              originalSender: stealthData.fromAddress,
              fromAddress: fromAddress,
              tokenAddress: tokenAddress,
              // @ts-ignore
              amount: ethers.BigNumber.from(amount).toBigInt().toString(),
              // @ts-ignore
              receiveAddress: toAddress,
            },
            addresses: [
              stealthData.fromAddress,
              fromAddress,
              tokenAddress,
              // @ts-ignore
              toAddress,
            ],
          })
        );

        umbraCache[networkNumber][stealthAddress][tokenAddress].amount =
          umbraCache[networkNumber][stealthAddress][tokenAddress].amount.sub(amount);
        if (umbraCache[networkNumber][stealthAddress][tokenAddress].amount.isNegative()) {
          delete umbraCache[networkNumber][stealthAddress][tokenAddress];
          if (Object.keys(umbraCache[networkNumber][stealthAddress]).length === 0) {
            delete umbraCache[networkNumber][stealthAddress];
          }
          if (Object.keys(umbraCache[networkNumber]).length === 0) {
            delete umbraCache[networkNumber];
          }
        }
      }
    }
  }

  return findings;
}

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  if (!txEvent.transaction.to) {
    return [];
  }

  const findings: Finding[] = [];
  const networkNumber = txEvent.network as number;

  const fromAddress = createAddress(txEvent.transaction.from);
  const toAddress = createAddress(txEvent.transaction.to);
  const value = ethers.BigNumber.from(txEvent.transaction.value);
  const calldata = txEvent.transaction.data;
  const funcHash = calldata.slice(0, 10).toLowerCase();

  if (toAddress === umbraContract) {
    const stealthAddress = createAddress(`0x${calldata.slice(34, 74)}`);
    const sponsor = createAddress(`0x${txEvent.transaction.data.slice(226, 266)}`);

    // detect `send` transactions
    if (funcHash === sendETHFunctionHash || funcHash === sendTokensFunctionHash) {
      const tokenSent: any = {};
      if (funcHash === sendETHFunctionHash) {
        if (value.gt(0)) {
          tokenSent[createAddress("0x0")] = value;
        }
      }

      if (funcHash === sendTokensFunctionHash) {
        const erc20_transfer_findings = await erc20TransfersHandler.handle(txEvent);
        for (const finding of erc20_transfer_findings) {
          const erc20TokenAddress = createAddress(finding.metadata.token);
          const erc20FromAddress = createAddress(finding.metadata.from);
          const erc20ToAddress = createAddress(finding.metadata.to);
          const erc20Amount = finding.metadata.amount;
          if (erc20ToAddress === umbraContract && erc20FromAddress === fromAddress) {
            if (erc20TokenAddress in tokenSent) {
              tokenSent[erc20TokenAddress] = tokenSent[erc20TokenAddress].add(erc20Amount);
            } else {
              tokenSent[erc20TokenAddress] = erc20Amount;
            }
          }
        }
      }

      for (const [tokenAddress, amount] of Object.entries(tokenSent)) {
        if (!(networkNumber in umbraCache)) {
          umbraCache[networkNumber] = {};
        }

        if (!(txEvent.network in umbraCache && stealthAddress in umbraCache[txEvent.network])) {
          umbraCache[networkNumber][stealthAddress] = {};
        }

        if (!(tokenAddress in umbraCache[networkNumber][stealthAddress])) {
          umbraCache[networkNumber][stealthAddress][tokenAddress] = {
            fromAddress: fromAddress,
            amount: ethers.BigNumber.from(amount),
          };
        } else {
          umbraCache[networkNumber][stealthAddress][tokenAddress].amount =
            umbraCache[networkNumber][stealthAddress][tokenAddress].amount.add(amount);
        }

        findings.push(
          Finding.fromObject({
            name: "Umbra Send Detected",
            description: "Umbra Send Detected",
            alertId: "UMBRA-SEND",
            severity: FindingSeverity.Info,
            type: FindingType.Info,
            metadata: {
              fromAddress: fromAddress,
              tokenAddress: tokenAddress,
              amount: (amount as ethers.BigNumber).toString(),
              stealthAddress: stealthAddress,
            },
            addresses: [
              fromAddress,
              tokenAddress,
              stealthAddress
            ],
          })
        );
      }
    }

    if (funcHash === withdrawTokensOnBehalfHash) {
      const withdrawFindings = await detectsUmbraWithdraw(txEvent, stealthAddress, sponsor);
      // @ts-ignore
      findings.push(...withdrawFindings)
    }
  }


  const withdrawFindings = await detectsUmbraWithdraw(txEvent, fromAddress);
  // @ts-ignore
  findings.push(...withdrawFindings)
  return findings;
};

// const handleBlock: HandleBlock = async (blockEvent: BlockEvent) => {
//   const findings: Finding[] = [];
//   // detect some block condition
//   return findings;
// }

export default {
  handleTransaction,
  // handleBlock
};
