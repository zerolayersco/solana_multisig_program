use anchor_lang::prelude::*;

declare_id!("Bn5XnfQeLWYgVFBe9SNmqagBkkLkikLk6vrQs94Viajb");

#[program]
pub mod first_project {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        
        // Explicitly validate that the account is new/uninitialized
        // This adds an extra safety layer on top of Anchor's init constraint
        if multisig.admin_count > 0 {
            return Err(error!(ErrorCode::AccountAlreadyInitialized));
        }
        
        // Set the initializer as the first admin
        multisig.admins[0] = ctx.accounts.initializer.key();
        multisig.admin_count = 1;
        
        // Initialize the add admin proposal state
        multisig.add_admin_signers = [Pubkey::default(); 10];
        multisig.add_admin_signatures = 0;
        multisig.add_admin_candidate = Pubkey::default();
        
        // Initialize the remove admin proposal state
        multisig.remove_admin_signers = [Pubkey::default(); 10];
        multisig.remove_admin_signatures = 0;
        multisig.remove_admin_candidate = Pubkey::default();
        
        // Initialize proposal counter
        multisig.proposal_counter = 0;
        
        msg!("Multi-signature program initialized with first admin: {:?}", ctx.accounts.initializer.key());
        Ok(())
    }

    pub fn is_admin(ctx: Context<IsAdmin>, wallet_pubkey: Pubkey) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        // Check if wallet_pubkey is in the admin list
        let mut is_admin = false;
        for i in 0..multisig.admin_count as usize {
            if multisig.admins[i] == wallet_pubkey {
                is_admin = true;
                break;
            }
        }
        
        if is_admin {
            msg!("Wallet {:?} is an admin", wallet_pubkey);
        } else {
            msg!("Wallet {:?} is NOT an admin", wallet_pubkey);
        }
        
        Ok(())
    }
    
    pub fn get_multisig_pubkey(ctx: Context<GetMultisigPubkey>) -> Result<()> {
        let multisig_pubkey = ctx.accounts.multisig.key();
        
        msg!("Multisig account public key: {:?}", multisig_pubkey);
        msg!("Total admins: {}", ctx.accounts.multisig.admin_count);
        msg!("Required signatures: {}", ctx.accounts.multisig.required_signatures());
        
        Ok(())
    }
    
    pub fn propose_add_admin(ctx: Context<ProposeAddAdmin>, new_admin: Pubkey) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        let proposer = ctx.accounts.proposer.key();
        
        // Check if new_admin is already an admin
        if multisig.is_admin(&new_admin) {
            return Err(error!(ErrorCode::AlreadyAdmin));
        }
        
        // Check if max admin count reached
        if multisig.admin_count as usize >= multisig.admins.len() {
            return Err(error!(ErrorCode::MaxAdminsReached));
        }
        
        // Check if there's already an active add admin proposal
        if multisig.add_admin_candidate != Pubkey::default() && multisig.add_admin_signatures > 0 {
            return Err(error!(ErrorCode::ProposalAlreadyActive));
        }
        
        // Reset any existing proposal
        multisig.add_admin_signers = [Pubkey::default(); 10];
        multisig.add_admin_signatures = 0;
        
        // Set the candidate and add first signature
        multisig.add_admin_candidate = new_admin;
        multisig.add_admin_signers[0] = proposer;
        multisig.add_admin_signatures = 1;
        
        msg!("Admin {:?} proposed adding {:?} as a new admin", proposer, new_admin);
        msg!("Signatures: 1/{} required", multisig.required_signatures());
        
        // NEW CODE: If there's only one admin, execute immediately since we've met the threshold
        if multisig.admin_count == 1 {
            // We already have the first signature (from the proposer), so we can execute
            
            // Store admin count in a local variable to avoid borrowing issue
            let admin_index = multisig.admin_count as usize;
            
            // Add the new admin to the list
            multisig.admins[admin_index] = new_admin;
            
            // Use checked_add for admin_count increment
            multisig.admin_count = multisig.admin_count.checked_add(1)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            // Reset the proposal
            multisig.add_admin_candidate = Pubkey::default();
            multisig.add_admin_signers = [Pubkey::default(); 10];
            multisig.add_admin_signatures = 0;
            
            msg!("Single admin mode: Immediately added new admin: {:?}", new_admin);
            msg!("Total admins: {}", multisig.admin_count);
        }
        
        Ok(())
    }
    
    pub fn sign_add_admin(ctx: Context<SignAddAdmin>) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        let signer = ctx.accounts.signer.key();
        
        // Ensure there's an active proposal
        if multisig.add_admin_candidate == Pubkey::default() {
            return Err(error!(ErrorCode::NoActiveProposal));
        }
        
        // Check if admin has already signed
        for i in 0..multisig.add_admin_signatures as usize {
            if multisig.add_admin_signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        // Add signer to the list
        let index = multisig.add_admin_signatures as usize;
        if index >= multisig.add_admin_signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        multisig.add_admin_signers[index] = signer;
        
        // Use checked_add for signature count increment
        multisig.add_admin_signatures = multisig.add_admin_signatures.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed to add {:?} as a new admin", signer, multisig.add_admin_candidate);
        msg!("Signatures: {}/{} required", 
            multisig.add_admin_signatures, 
            multisig.required_signatures());
        
        // NEW CODE: Check if we've reached the signature threshold and execute the change
        if multisig.add_admin_signatures >= multisig.required_signatures() {
            // Get the new admin candidate
            let new_admin = multisig.add_admin_candidate;
            
            // Check if new_admin is already an admin (double check in case they were added elsewhere)
            if multisig.is_admin(&new_admin) {
                return Err(error!(ErrorCode::AlreadyAdmin));
            }
            
            // Store admin count in a local variable to avoid borrowing issue
            let admin_index = multisig.admin_count as usize;
            
            // Check for array bounds before adding
            if admin_index >= multisig.admins.len() {
                return Err(error!(ErrorCode::MaxAdminsReached));
            }
            
            // Add the new admin to the list
            multisig.admins[admin_index] = new_admin;
            
            // Use checked_add for admin_count increment
            multisig.admin_count = multisig.admin_count.checked_add(1)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            // Reset the proposal
            multisig.add_admin_candidate = Pubkey::default();
            multisig.add_admin_signers = [Pubkey::default(); 10];
            multisig.add_admin_signatures = 0;
            
            msg!("Signature threshold met. Added new admin: {:?}", new_admin);
            msg!("Total admins: {}", multisig.admin_count);
        }
        
        Ok(())
    }
    
    pub fn propose_withdrawal(
        ctx: Context<ProposeWithdrawal>, 
        amount: u64, 
        description: String
    ) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        let proposal = &mut ctx.accounts.proposal;
        let proposer = ctx.accounts.proposer.key();
        
        // Prevent zero-amount withdrawal proposals
        if amount == 0 {
            return Err(error!(ErrorCode::ZeroAmountWithdrawal));
        }
        
        // Validate that description length doesn't exceed allocated space
        const MAX_DESCRIPTION_LENGTH: usize = 200;
        if description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(error!(ErrorCode::DescriptionTooLong));
        }
        
        // Store next proposal ID for use throughout this function
        let next_proposal_id = multisig.proposal_counter.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        // Initialize the proposal account
        proposal.multisig = multisig.key();
        proposal.proposal_id = next_proposal_id; // Use the calculated next ID
        proposal.proposer = proposer;
        proposal.destination = ctx.accounts.destination.key();
        proposal.amount = amount;
        proposal.description = description;
        proposal.executed = false;
        proposal.signers = [Pubkey::default(); 10];
        proposal.signature_count = 0;
        
        // Add proposer as the first signer
        proposal.signers[0] = proposer;
        proposal.signature_count = 1;
        
        // Increment the proposal counter AFTER successful initialization
        multisig.proposal_counter = next_proposal_id;
        
        msg!("Withdrawal proposal created by {:?}", proposer);
        msg!("Proposal ID: {}", next_proposal_id);
        msg!("Amount: {} lamports", amount);
        msg!("Destination: {:?}", ctx.accounts.destination.key());
        msg!("Signatures: 1/{} required", multisig.required_signatures());
        
        // If only one admin exists, execute right away since the signature threshold is met
        if multisig.admin_count == 1 {
            // CHANGE: Mark as executed FIRST, before transferring funds
            proposal.executed = true;
            
            // Transfer the funds
            let amount = proposal.amount;
            let source_starting_lamports = ctx.accounts.multisig.to_account_info().lamports();
            
            // Calculate minimum balance for rent exemption
            let min_rent = ctx.accounts.rent.minimum_balance(ctx.accounts.multisig.to_account_info().data_len());
            
            // Make sure we have enough funds and won't drop below rent exemption
            if source_starting_lamports < amount {
                return Err(error!(ErrorCode::InsufficientFunds));
            }
            
            // Ensure we maintain rent exemption with checked math
            if source_starting_lamports < amount.checked_add(min_rent).ok_or(ErrorCode::ArithmeticOverflow)? {
                return Err(error!(ErrorCode::InsufficientFundsForRentExemption));
            }
            
            let dest_starting_lamports = ctx.accounts.destination.lamports();
            
            // Transfer lamports with checked math
            **ctx.accounts.multisig.to_account_info().lamports.borrow_mut() = source_starting_lamports
                .checked_sub(amount)
                .ok_or(ErrorCode::ArithmeticUnderflow)?;
            
            **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
                .checked_add(amount)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            msg!("Withdrawal executed immediately. Transferred {} lamports to {:?}", amount, ctx.accounts.destination.key());
        }
        
        Ok(())
    }
    
    pub fn sign_withdrawal(ctx: Context<SignWithdrawal>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        let proposal = &mut ctx.accounts.proposal;
        let signer = ctx.accounts.signer.key();
        
        // Check if admin has already signed
        for i in 0..proposal.signature_count as usize {
            if proposal.signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        // Add signer to the list
        let index = proposal.signature_count as usize;
        if index >= proposal.signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        proposal.signers[index] = signer;
        
        // Use checked_add for signature count increment
        proposal.signature_count = proposal.signature_count.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed withdrawal proposal {}", signer, proposal.proposal_id);
        msg!("Signatures: {}/{} required", proposal.signature_count, multisig.required_signatures());
        
        // Check if we have enough signatures to execute
        if proposal.signature_count >= multisig.required_signatures() {
            // Mark as executed FIRST, before transferring funds
            proposal.executed = true;
            
            // Transfer the funds
            let amount = proposal.amount;
            let source_starting_lamports = ctx.accounts.multisig.to_account_info().lamports();
            
            // Calculate minimum balance for rent exemption
            let min_rent = ctx.accounts.rent.minimum_balance(ctx.accounts.multisig.to_account_info().data_len());
            
            // Make sure we have enough funds and won't drop below rent exemption
            if source_starting_lamports < amount {
                return Err(error!(ErrorCode::InsufficientFunds));
            }
            
            // Ensure we maintain rent exemption with checked math
            if source_starting_lamports < amount.checked_add(min_rent).ok_or(ErrorCode::ArithmeticOverflow)? {
                return Err(error!(ErrorCode::InsufficientFundsForRentExemption));
            }
            
            let dest_starting_lamports = ctx.accounts.destination.lamports();
            
            // Transfer lamports with checked math
            **ctx.accounts.multisig.to_account_info().lamports.borrow_mut() = source_starting_lamports
                .checked_sub(amount)
                .ok_or(ErrorCode::ArithmeticUnderflow)?;
            
            **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
                .checked_add(amount)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            msg!("Signature threshold met. Withdrawal executed. Transferred {} lamports to {:?}", amount, ctx.accounts.destination.key());
        }
        
        Ok(())
    }

    pub fn propose_remove_admin(ctx: Context<ProposeRemoveAdmin>, admin_to_remove: Pubkey) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        let proposer = ctx.accounts.proposer.key();
        
        // Check if admin_to_remove is actually an admin
        if !multisig.is_admin(&admin_to_remove) {
            return Err(error!(ErrorCode::NotAdmin));
        }
        
        // NEW: Prevent proposing self-removal
        if proposer == admin_to_remove {
            return Err(error!(ErrorCode::CannotProposeSelfRemoval));
        }
        
        // Ensure we maintain at least one admin
        if multisig.admin_count <= 1 {
            return Err(error!(ErrorCode::LastAdminCannotBeRemoved));
        }
        
        // Check if there's already an active remove admin proposal
        if multisig.remove_admin_candidate != Pubkey::default() && multisig.remove_admin_signatures > 0 {
            return Err(error!(ErrorCode::ProposalAlreadyActive));
        }
        
        // Reset any existing proposal
        multisig.remove_admin_signers = [Pubkey::default(); 10];
        multisig.remove_admin_signatures = 0;
        
        // Set the candidate for removal and add first signature
        multisig.remove_admin_candidate = admin_to_remove;
        multisig.remove_admin_signers[0] = proposer;
        multisig.remove_admin_signatures = 1;
        
        msg!("Admin {:?} proposed removing {:?} as an admin", proposer, admin_to_remove);
        msg!("Signatures: 1/{} required", multisig.required_signatures());
        
        Ok(())
    }
    
    pub fn sign_remove_admin(ctx: Context<SignRemoveAdmin>) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        let signer = ctx.accounts.signer.key();
        
        // Ensure there's an active proposal
        if multisig.remove_admin_candidate == Pubkey::default() {
            return Err(error!(ErrorCode::NoActiveProposal));
        }
        
        // Check if admin has already signed
        for i in 0..multisig.remove_admin_signatures as usize {
            if multisig.remove_admin_signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        // Add signer to the list
        let index = multisig.remove_admin_signatures as usize;
        if index >= multisig.remove_admin_signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        multisig.remove_admin_signers[index] = signer;
        
        // Use checked_add for signature count increment
        multisig.remove_admin_signatures = multisig.remove_admin_signatures.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed to remove {:?} as an admin", signer, multisig.remove_admin_candidate);
        msg!("Signatures: {}/{} required", 
            multisig.remove_admin_signatures, 
            multisig.required_signatures());
        
        // NEW CODE: Check if we've reached the signature threshold and execute the change
        if multisig.remove_admin_signatures >= multisig.required_signatures() {
            // Get the admin candidate to remove
            let admin_to_remove = multisig.remove_admin_candidate;
            
            // Check if admin_to_remove is still an admin
            if !multisig.is_admin(&admin_to_remove) {
                return Err(error!(ErrorCode::NotAdmin));
            }
            
            // Ensure we maintain at least one admin
            if multisig.admin_count <= 1 {
                return Err(error!(ErrorCode::LastAdminCannotBeRemoved));
            }
            
            // Find the index of the admin to remove
            let mut admin_index = multisig.admin_count as usize; // Default to an invalid index
            for i in 0..multisig.admin_count as usize {
                if multisig.admins[i] == admin_to_remove {
                    admin_index = i;
                    break;
                }
            }
            
            // If admin not found (should not happen given the check above)
            if admin_index >= multisig.admin_count as usize {
                return Err(error!(ErrorCode::NotAdmin));
            }
            
            // Store the current admin count in a local variable to avoid borrowing issues
            let current_admin_count = multisig.admin_count as usize;
            
            // Remove the admin by shifting all admins above it down by one
            for i in admin_index..(current_admin_count - 1) {
                multisig.admins[i] = multisig.admins[i + 1];
            }
            
            // Clear the last slot and decrement count
            multisig.admins[current_admin_count - 1] = Pubkey::default();
            
            // Use checked_sub for admin_count decrement
            multisig.admin_count = multisig.admin_count.checked_sub(1)
                .ok_or(ErrorCode::ArithmeticUnderflow)?;
            
            // Reset the proposal
            multisig.remove_admin_candidate = Pubkey::default();
            multisig.remove_admin_signers = [Pubkey::default(); 10];
            multisig.remove_admin_signatures = 0;
            
            msg!("Signature threshold met. Removed admin: {:?}", admin_to_remove);
            msg!("Total admins: {}", multisig.admin_count);
        }
        
        Ok(())
    }
    
    pub fn cancel_proposal(ctx: Context<CancelProposal>) -> Result<()> {
        let proposal = &ctx.accounts.proposal;
        
        // Verification is handled by account constraints (only proposer can cancel)
        // Log the proposal cancellation
        msg!("Withdrawal proposal {} cancelled by proposer", proposal.proposal_id);
        msg!("Proposal funds returned to proposer");
        
        Ok(())
    }
    
    pub fn get_multisig_details(ctx: Context<GetMultisigDetails>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        // Display basic multisig information
        msg!("Multisig account public key: {:?}", multisig.key());
        msg!("Total admins: {}", multisig.admin_count);
        msg!("Required signatures: {}", multisig.required_signatures());
        msg!("Proposal counter: {}", multisig.proposal_counter);
        
        // Display admin list
        msg!("Admin list:");
        for i in 0..multisig.admin_count as usize {
            msg!("  Admin {}: {:?}", i + 1, multisig.admins[i]);
        }
        
        // Check if there's an active add admin proposal
        if multisig.add_admin_candidate != Pubkey::default() {
            msg!("Active add admin proposal:");
            msg!("  Candidate: {:?}", multisig.add_admin_candidate);
            msg!("  Signatures: {}/{}", multisig.add_admin_signatures, multisig.required_signatures());
        } else {
            msg!("No active add admin proposal");
        }
        
        // Check if there's an active remove admin proposal
        if multisig.remove_admin_candidate != Pubkey::default() {
            msg!("Active remove admin proposal:");
            msg!("  Admin to remove: {:?}", multisig.remove_admin_candidate);
            msg!("  Signatures: {}/{}", multisig.remove_admin_signatures, multisig.required_signatures());
        } else {
            msg!("No active remove admin proposal");
        }
        
        Ok(())
    }
    
    pub fn get_proposal_details(ctx: Context<GetProposalDetails>) -> Result<()> {
        let proposal = &ctx.accounts.proposal;
        
        // Display proposal information
        msg!("Withdrawal proposal details:");
        msg!("  Proposal ID: {}", proposal.proposal_id);
        msg!("  Multisig account: {:?}", proposal.multisig);
        msg!("  Proposer: {:?}", proposal.proposer);
        msg!("  Destination: {:?}", proposal.destination);
        msg!("  Amount: {} lamports", proposal.amount);
        msg!("  Description: {}", proposal.description);
        msg!("  Executed: {}", proposal.executed);
        msg!("  Signatures: {}", proposal.signature_count);
        
        // Display signers
        msg!("  Signers:");
        for i in 0..proposal.signature_count as usize {
            msg!("    Signer {}: {:?}", i + 1, proposal.signers[i]);
        }
        
        Ok(())
    }
    
    pub fn get_admin_proposals(ctx: Context<GetAdminProposals>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        // Check for add admin proposal
        if multisig.add_admin_candidate != Pubkey::default() {
            msg!("Active add admin proposal found:");
            msg!("  Candidate to add: {:?}", multisig.add_admin_candidate);
            msg!("  Signatures: {}/{} required", 
                multisig.add_admin_signatures, 
                multisig.required_signatures());
            
            // List signers
            msg!("  Signers:");
            for i in 0..multisig.add_admin_signatures as usize {
                msg!("    Signer {}: {:?}", i + 1, multisig.add_admin_signers[i]);
            }
        } else {
            msg!("No active add admin proposal");
        }
        
        // Check for remove admin proposal
        if multisig.remove_admin_candidate != Pubkey::default() {
            msg!("Active remove admin proposal found:");
            msg!("  Admin to remove: {:?}", multisig.remove_admin_candidate);
            msg!("  Signatures: {}/{} required", 
                multisig.remove_admin_signatures, 
                multisig.required_signatures());
            
            // List signers
            msg!("  Signers:");
            for i in 0..multisig.remove_admin_signatures as usize {
                msg!("    Signer {}: {:?}", i + 1, multisig.remove_admin_signers[i]);
            }
        } else {
            msg!("No active remove admin proposal");
        }
        
        Ok(())
    }
    
    pub fn get_proposal_count(ctx: Context<GetProposalCount>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        msg!("Total proposals created: {}", multisig.proposal_counter);
        
        Ok(())
    }
}

// Multi-signature program state to track admins
#[account]
pub struct Multisig {
    // Array to store admin public keys (max 10 admins)
    pub admins: [Pubkey; 10],
    // Count of current admins
    pub admin_count: u8,
    // Add admin proposal state
    pub add_admin_signers: [Pubkey; 10],
    pub add_admin_signatures: u8,
    pub add_admin_candidate: Pubkey,
    // Remove admin proposal state
    pub remove_admin_signers: [Pubkey; 10],
    pub remove_admin_signatures: u8,
    pub remove_admin_candidate: Pubkey,
    // Proposal counter for generating unique PDAs
    pub proposal_counter: u64,
}

// Withdrawal proposal account
#[account]
pub struct WithdrawalProposal {
    // Reference to the multisig this proposal belongs to
    pub multisig: Pubkey,
    // Proposal ID
    pub proposal_id: u64,
    // Admin who proposed the withdrawal
    pub proposer: Pubkey,
    // Destination wallet to receive funds
    pub destination: Pubkey,
    // Amount to withdraw in lamports
    pub amount: u64,
    // Optional description/reason for the withdrawal (max 200 chars)
    pub description: String,
    // Whether the proposal has been executed
    pub executed: bool,
    // Admins who have signed the proposal
    pub signers: [Pubkey; 10],
    // Count of signatures
    pub signature_count: u8,
}

// Helper functions for multisig logic
impl Multisig {
    // Function to check if a pubkey is an admin
    pub fn is_admin(&self, pubkey: &Pubkey) -> bool {
        for i in 0..self.admin_count as usize {
            if self.admins[i] == *pubkey {
                return true;
            }
        }
        false
    }
    
    // Function to determine how many signatures are required
    pub fn required_signatures(&self) -> u8 {
        if self.admin_count == 1 {
            // If only one admin exists, only one signature is required
            1
        } else {
            // For multiple admins, we could implement various rules here
            // For now, let's say we require a majority with checked arithmetic
            self.admin_count
                .checked_div(2)
                .and_then(|half| half.checked_add(1))
                .unwrap_or(1) // Fallback to 1 in case of overflow/error
        }
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    
    #[account(
        init,
        payer = initializer,
        space = 8 + 32 * 10 + 1 + 32 * 10 + 1 + 32 + 32 * 10 + 1 + 32 + 8, 
        // 8 discriminator + 
        // admins array (32*10) + count (1) + 
        // add admin state (32*10 + 1 + 32) + 
        // remove admin state (32*10 + 1 + 32) + 
        // proposal counter (8)
    )]
    pub multisig: Account<'info, Multisig>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IsAdmin<'info> {
    // No signer required, this is a read-only operation
    #[account(
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetMultisigPubkey<'info> {
    // No signer required, this is a read-only operation that anyone can perform
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct ProposeAddAdmin<'info> {
    // Admin must sign to propose adding a new admin
    pub proposer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&proposer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct SignAddAdmin<'info> {
    // Admin must sign to approve adding a new admin
    pub signer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&signer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
#[instruction(amount: u64, description: String)]
pub struct ProposeWithdrawal<'info> {
    // Admin must sign to propose a withdrawal
    #[account(mut)]
    pub proposer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&proposer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
    
    // Destination account to receive funds
    /// CHECK: This is not being read from or written to
    pub destination: UncheckedAccount<'info>,
    
    // Withdrawal proposal PDA
    #[account(
        init,
        payer = proposer,
        // Fixed space allocation with room for a description of up to 200 chars
        space = 8 + 32 + 8 + 32 + 32 + 8 + 4 + 200 + 1 + 32 * 10 + 1,
        seeds = [
            b"withdrawal".as_ref(), 
            multisig.key().as_ref(), 
            &(multisig.proposal_counter + 1).to_le_bytes()
        ],
        bump
    )]
    pub proposal: Account<'info, WithdrawalProposal>,
    
    pub system_program: Program<'info, System>,
    
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SignWithdrawal<'info> {
    // Admin must sign to approve a withdrawal
    pub signer: Signer<'info>,
    
    // Read the multisig account
    #[account(
        mut,
        constraint = multisig.key() == proposal.multisig @ ErrorCode::InvalidProposal,
        constraint = multisig.is_admin(&signer.key()) @ ErrorCode::NotAdmin
    )]
    pub multisig: Account<'info, Multisig>,
    
    // Find the proposal with the same seeds used to create it
    #[account(
        mut,
        seeds = [
            b"withdrawal".as_ref(), 
            multisig.key().as_ref(), 
            &proposal.proposal_id.to_le_bytes()
        ],
        bump,
        constraint = !proposal.executed @ ErrorCode::ProposalAlreadyExecuted
    )]
    pub proposal: Account<'info, WithdrawalProposal>,
    
    // Destination account to receive funds
    #[account(
        mut,
        constraint = destination.key() == proposal.destination @ ErrorCode::InvalidDestination
    )]
    /// CHECK: This account is just receiving funds
    pub destination: UncheckedAccount<'info>,
    
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ProposeRemoveAdmin<'info> {
    // Admin must sign to propose removing an admin
    pub proposer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&proposer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct SignRemoveAdmin<'info> {
    // Admin must sign to approve removing an admin
    pub signer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&signer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct CancelProposal<'info> {
    // Only the original proposer can cancel
    #[account(mut)]
    pub proposer: Signer<'info>,
    
    // The multisig account for reference
    #[account(
        constraint = multisig.key() == proposal.multisig @ ErrorCode::InvalidProposal,
        // ADD: Ensure multisig is properly initialized with admins
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
    
    // The proposal that is being cancelled
    #[account(
        mut,
        seeds = [
            b"withdrawal".as_ref(), 
            multisig.key().as_ref(), 
            &proposal.proposal_id.to_le_bytes()
        ],
        bump,
        constraint = proposal.proposer == proposer.key() @ ErrorCode::NotProposer,
        constraint = !proposal.executed @ ErrorCode::ProposalAlreadyExecuted,
        close = proposer
    )]
    pub proposal: Account<'info, WithdrawalProposal>,
}

#[derive(Accounts)]
pub struct GetMultisigDetails<'info> {
    // No signer required, this is a read-only operation
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetProposalDetails<'info> {
    // No signer required, this is a read-only operation
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
    
    #[account(
        constraint = proposal.multisig == multisig.key() @ ErrorCode::InvalidProposal,
        // ADD: Ensure proposal is initialized with valid values
        constraint = proposal.proposal_id > 0 @ ErrorCode::AccountNotInitialized,
        constraint = proposal.proposer != Pubkey::default() @ ErrorCode::AccountNotInitialized
    )]
    pub proposal: Account<'info, WithdrawalProposal>,
}

#[derive(Accounts)]
pub struct GetAdminProposals<'info> {
    // No signer required, this is a read-only operation
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetProposalCount<'info> {
    // No signer required, this is a read-only operation
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("The provided public key is already an admin")]
    AlreadyAdmin,
    #[msg("Maximum number of admins reached")]
    MaxAdminsReached,
    #[msg("Only admins can perform this action")]
    NotAdmin,
    #[msg("This admin has already signed")]
    AlreadySigned,
    #[msg("Maximum number of signatures reached")]
    MaxSignaturesReached,
    #[msg("Not enough signatures to perform this action")]
    InsufficientSignatures,
    #[msg("No active proposal to sign")]
    NoActiveProposal,
    #[msg("This proposal has already been executed")]
    ProposalAlreadyExecuted,
    #[msg("Insufficient funds for this withdrawal")]
    InsufficientFunds,
    #[msg("Invalid proposal")]
    InvalidProposal,
    #[msg("Invalid destination")]
    InvalidDestination,
    #[msg("Cannot remove the last admin")]
    LastAdminCannotBeRemoved,
    #[msg("Only the proposer can cancel this proposal")]
    NotProposer,
    #[msg("Account is already initialized")]
    AccountAlreadyInitialized,
    #[msg("Withdrawal would leave account with insufficient funds for rent exemption")]
    InsufficientFundsForRentExemption,
    #[msg("Description too long (maximum 200 characters)")]
    DescriptionTooLong,
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow occurred")]
    ArithmeticUnderflow,
    #[msg("Withdrawal amount must be greater than zero")]
    ZeroAmountWithdrawal,
    #[msg("A proposal is already active, complete or cancel it before creating a new one")]
    ProposalAlreadyActive,
    #[msg("Cannot propose self-removal")]
    CannotProposeSelfRemoval,
    #[msg("Account is not initialized")]
    AccountNotInitialized,
}
