# Umbra Detection Agent

## Description

This agent detects the stealth address of Umbra Protocol users.

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

