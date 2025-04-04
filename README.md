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

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/solana-multisig-program.git
cd solana-multisig-program

# Install dependencies
yarn install

# Build the program
anchor build

# Deploy to localnet for testing
anchor deploy
```

## Usage Guide

### Initialize a new multisig

Creates a new multisig wallet with the initializer as the first admin.

```bash
# Using Anchor CLI
anchor run initialize
```

### Add a new admin

1. Propose adding a new admin (requires an existing admin)
2. Other admins sign the proposal
3. Once threshold is met, execute the addition

```bash
# Propose a new admin
anchor run propose-add-admin -- --admin-pubkey <PUBKEY>

# Sign the proposal (from another admin)
anchor run sign-add-admin

# Execute the proposal when enough signatures are collected
anchor run execute-add-admin
```

### Remove an admin

1. Propose removing an admin (requires an existing admin)
2. Other admins sign the proposal
3. Once threshold is met, execute the removal

```bash
# Propose removing an admin
anchor run propose-remove-admin -- --admin-pubkey <PUBKEY>

# Sign the proposal (from another admin)
anchor run sign-remove-admin

# Execute the proposal when enough signatures are collected
anchor run execute-remove-admin
```

### Create a withdrawal

1. Propose a withdrawal (requires an admin)
2. Other admins sign the proposal
3. Once threshold is met, funds are automatically transferred

```bash
# Propose a withdrawal
anchor run propose-withdrawal -- --amount <LAMPORTS> --destination <PUBKEY> --description "Purpose of withdrawal"

# Sign the proposal (from another admin)
anchor run sign-withdrawal -- --proposal-id <ID>
```

### Query Information

View details about the multisig wallet and proposals.

```bash
# Get multisig details
anchor run get-multisig-details

# Check if an address is an admin
anchor run is-admin -- --pubkey <PUBKEY>

# Get details about a specific proposal
anchor run get-proposal-details -- --proposal-id <ID>

# View active admin proposals
anchor run get-admin-proposals
```

## Security Considerations

- Always verify the destination address before signing withdrawal proposals
- Keep admin private keys secure
- Ensure adequate redundancy (avoid situations where lost keys make funds inaccessible)
- Consider the trade-off between security (more admins/signatures) and operational efficiency

## License

This project is licensed under the MIT License - see the LICENSE file for details. 