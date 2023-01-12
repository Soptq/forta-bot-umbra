# Umbra Detection Agent

## Description

This agent detects the stealth address of Umbra Protocol users. This bot is live on:

https://explorer.forta.network/bot/0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0

## Supported Chains

- All chains the Umbra Protocol on.

## Alerts

- Umbra Send Detected
  - Fired when a deposit is found using Umbra Protocol
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - fromAddress: the depositor
    - tokenAddress: what to deposit
    - amount: the amount to deposit
    - stealthAddress: the stealth address of the depositor
- Umbra Receive Detected
  - Fired when a withdrawal is found using Umbra Protocol
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - originalSender: the sender of the funds.
    - fromAddress: the stealth address,
    - tokenAddress: what to withdraw,
    - amount: the amount to withdraw
    - receiveAddress: the receiver

