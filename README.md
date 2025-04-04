# Solana Multisig Program

A secure, flexible multi-signature wallet implementation on Solana blockchain using the Anchor framework.

## Overview

This multisig program enables multiple administrators to collectively control funds through a configurable approval threshold. The program requires majority consensus for critical operations like withdrawals and admin management, providing enhanced security for shared wallets.

## Features

- **Secure Admin Management**
  - Add new admins through multi-signature approval
  - Remove existing admins with proper authorization
  - Protections to prevent removal of the last admin

- **Withdrawal Management**
  - Create withdrawal proposals with custom descriptions
  - Sign proposals as an admin
  - Automatic execution when signature threshold is met
  - Cancel proposals (only by original proposer)

- **Transparent Operations**
  - View detailed multisig account information
  - Check admin status
  - View active proposals
  - Track signatures and approvals

- **Security Features**
  - Majority-based approval threshold
  - Protection against double-signing
  - Validation for all operations
  - Proper PDA-based proposal storage

## Technical Details

- Built with Anchor framework for Solana
- Uses Program Derived Addresses (PDAs) for secure proposal storage
- Implements proper account validation and constraint checks
- Features comprehensive error handling
