use anchor_lang::prelude::*;

declare_id!("Bn5XnfQeLWYgVFBe9SNmqagBkkLkikLk6vrQs94Viajb");

#[program]
pub mod first_project {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let multisig = &mut ctx.accounts.multisig;
        
        if multisig.admin_count > 0 {
            return Err(error!(ErrorCode::AccountAlreadyInitialized));
        }
        
        multisig.admins[0] = ctx.accounts.initializer.key();
        multisig.admin_count = 1;
        
        multisig.add_admin_signers = [Pubkey::default(); 10];
        multisig.add_admin_signatures = 0;
        multisig.add_admin_candidate = Pubkey::default();
        
        multisig.remove_admin_signers = [Pubkey::default(); 10];
        multisig.remove_admin_signatures = 0;
        multisig.remove_admin_candidate = Pubkey::default();
        
        multisig.proposal_counter = 0;
        
        msg!("Multi-signature program initialized with first admin: {:?}", ctx.accounts.initializer.key());
        Ok(())
    }

    pub fn is_admin(ctx: Context<IsAdmin>, wallet_pubkey: Pubkey) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
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
        
        if multisig.is_admin(&new_admin) {
            return Err(error!(ErrorCode::AlreadyAdmin));
        }
        
        if multisig.admin_count as usize >= multisig.admins.len() {
            return Err(error!(ErrorCode::MaxAdminsReached));
        }
        
        if multisig.add_admin_candidate != Pubkey::default() && multisig.add_admin_signatures > 0 {
            return Err(error!(ErrorCode::ProposalAlreadyActive));
        }
        
        multisig.add_admin_signers = [Pubkey::default(); 10];
        multisig.add_admin_signatures = 0;
        
        multisig.add_admin_candidate = new_admin;
        multisig.add_admin_signers[0] = proposer;
        multisig.add_admin_signatures = 1;
        
        msg!("Admin {:?} proposed adding {:?} as a new admin", proposer, new_admin);
        msg!("Signatures: 1/{} required", multisig.required_signatures());
        
        if multisig.admin_count == 1 {
            let admin_index = multisig.admin_count as usize;
            
            multisig.admins[admin_index] = new_admin;
            
            multisig.admin_count = multisig.admin_count.checked_add(1)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
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
        
        if multisig.add_admin_candidate == Pubkey::default() {
            return Err(error!(ErrorCode::NoActiveProposal));
        }
        
        for i in 0..multisig.add_admin_signatures as usize {
            if multisig.add_admin_signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        let index = multisig.add_admin_signatures as usize;
        if index >= multisig.add_admin_signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        multisig.add_admin_signers[index] = signer;
        
        multisig.add_admin_signatures = multisig.add_admin_signatures.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed to add {:?} as a new admin", signer, multisig.add_admin_candidate);
        msg!("Signatures: {}/{} required", 
            multisig.add_admin_signatures, 
            multisig.required_signatures());
        
        if multisig.add_admin_signatures >= multisig.required_signatures() {
            let new_admin = multisig.add_admin_candidate;
            
            if multisig.is_admin(&new_admin) {
                return Err(error!(ErrorCode::AlreadyAdmin));
            }
            
            let admin_index = multisig.admin_count as usize;
            
            if admin_index >= multisig.admins.len() {
                return Err(error!(ErrorCode::MaxAdminsReached));
            }
            
            multisig.admins[admin_index] = new_admin;
            
            multisig.admin_count = multisig.admin_count.checked_add(1)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
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
        
        if amount == 0 {
            return Err(error!(ErrorCode::ZeroAmountWithdrawal));
        }
        
        const MAX_DESCRIPTION_LENGTH: usize = 200;
        if description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(error!(ErrorCode::DescriptionTooLong));
        }
        
        let next_proposal_id = multisig.proposal_counter.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        proposal.multisig = multisig.key();
        proposal.proposal_id = next_proposal_id;
        proposal.proposer = proposer;
        proposal.destination = ctx.accounts.destination.key();
        proposal.amount = amount;
        proposal.description = description;
        proposal.executed = false;
        proposal.signers = [Pubkey::default(); 10];
        proposal.signature_count = 0;
        
        proposal.signers[0] = proposer;
        proposal.signature_count = 1;
        
        multisig.proposal_counter = next_proposal_id;
        
        msg!("Withdrawal proposal created by {:?}", proposer);
        msg!("Proposal ID: {}", next_proposal_id);
        msg!("Amount: {} lamports", amount);
        msg!("Destination: {:?}", ctx.accounts.destination.key());
        msg!("Signatures: 1/{} required", multisig.required_signatures());
        
        if multisig.admin_count == 1 {
            proposal.executed = true;
            
            let amount = proposal.amount;
            let source_starting_lamports = ctx.accounts.multisig.to_account_info().lamports();
            
            let min_rent = ctx.accounts.rent.minimum_balance(ctx.accounts.multisig.to_account_info().data_len());
            
            if source_starting_lamports < amount {
                return Err(error!(ErrorCode::InsufficientFunds));
            }
            
            if source_starting_lamports < amount.checked_add(min_rent).ok_or(ErrorCode::ArithmeticOverflow)? {
                return Err(error!(ErrorCode::InsufficientFundsForRentExemption));
            }
            
            let dest_starting_lamports = ctx.accounts.destination.lamports();
            
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
        
        for i in 0..proposal.signature_count as usize {
            if proposal.signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        let index = proposal.signature_count as usize;
        if index >= proposal.signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        proposal.signers[index] = signer;
        
        proposal.signature_count = proposal.signature_count.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed withdrawal proposal {}", signer, proposal.proposal_id);
        msg!("Signatures: {}/{} required", proposal.signature_count, multisig.required_signatures());
        
        if proposal.signature_count >= multisig.required_signatures() {
            proposal.executed = true;
            
            let amount = proposal.amount;
            let source_starting_lamports = ctx.accounts.multisig.to_account_info().lamports();
            
            let min_rent = ctx.accounts.rent.minimum_balance(ctx.accounts.multisig.to_account_info().data_len());
            
            if source_starting_lamports < amount {
                return Err(error!(ErrorCode::InsufficientFunds));
            }
            
            if source_starting_lamports < amount.checked_add(min_rent).ok_or(ErrorCode::ArithmeticOverflow)? {
                return Err(error!(ErrorCode::InsufficientFundsForRentExemption));
            }
            
            let dest_starting_lamports = ctx.accounts.destination.lamports();
            
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
        
        if !multisig.is_admin(&admin_to_remove) {
            return Err(error!(ErrorCode::NotAdmin));
        }
        
        if proposer == admin_to_remove {
            return Err(error!(ErrorCode::CannotProposeSelfRemoval));
        }
        
        if multisig.admin_count <= 1 {
            return Err(error!(ErrorCode::LastAdminCannotBeRemoved));
        }
        
        if multisig.remove_admin_candidate != Pubkey::default() && multisig.remove_admin_signatures > 0 {
            return Err(error!(ErrorCode::ProposalAlreadyActive));
        }
        
        multisig.remove_admin_signers = [Pubkey::default(); 10];
        multisig.remove_admin_signatures = 0;
        
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
        
        if multisig.remove_admin_candidate == Pubkey::default() {
            return Err(error!(ErrorCode::NoActiveProposal));
        }
        
        for i in 0..multisig.remove_admin_signatures as usize {
            if multisig.remove_admin_signers[i] == signer {
                return Err(error!(ErrorCode::AlreadySigned));
            }
        }
        
        let index = multisig.remove_admin_signatures as usize;
        if index >= multisig.remove_admin_signers.len() {
            return Err(error!(ErrorCode::MaxSignaturesReached));
        }
        
        multisig.remove_admin_signers[index] = signer;
        
        multisig.remove_admin_signatures = multisig.remove_admin_signatures.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        msg!("Admin {:?} signed to remove {:?} as an admin", signer, multisig.remove_admin_candidate);
        msg!("Signatures: {}/{} required", 
            multisig.remove_admin_signatures, 
            multisig.required_signatures());
        
        if multisig.remove_admin_signatures >= multisig.required_signatures() {
            let admin_to_remove = multisig.remove_admin_candidate;
            
            if !multisig.is_admin(&admin_to_remove) {
                return Err(error!(ErrorCode::NotAdmin));
            }
            
            if multisig.admin_count <= 1 {
                return Err(error!(ErrorCode::LastAdminCannotBeRemoved));
            }
            
            let mut admin_index = multisig.admin_count as usize;
            for i in 0..multisig.admin_count as usize {
                if multisig.admins[i] == admin_to_remove {
                    admin_index = i;
                    break;
                }
            }
            
            if admin_index >= multisig.admin_count as usize {
                return Err(error!(ErrorCode::NotAdmin));
            }
            
            let current_admin_count = multisig.admin_count as usize;
            
            for i in admin_index..(current_admin_count - 1) {
                multisig.admins[i] = multisig.admins[i + 1];
            }
            
            multisig.admins[current_admin_count - 1] = Pubkey::default();
            
            multisig.admin_count = multisig.admin_count.checked_sub(1)
                .ok_or(ErrorCode::ArithmeticUnderflow)?;
            
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
        
        msg!("Withdrawal proposal {} cancelled by proposer", proposal.proposal_id);
        msg!("Proposal funds returned to proposer");
        
        Ok(())
    }
    
    pub fn get_multisig_details(ctx: Context<GetMultisigDetails>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        msg!("Multisig account public key: {:?}", multisig.key());
        msg!("Total admins: {}", multisig.admin_count);
        msg!("Required signatures: {}", multisig.required_signatures());
        msg!("Proposal counter: {}", multisig.proposal_counter);
        
        msg!("Admin list:");
        for i in 0..multisig.admin_count as usize {
            msg!("  Admin {}: {:?}", i + 1, multisig.admins[i]);
        }
        
        if multisig.add_admin_candidate != Pubkey::default() {
            msg!("Active add admin proposal:");
            msg!("  Candidate: {:?}", multisig.add_admin_candidate);
            msg!("  Signatures: {}/{}", multisig.add_admin_signatures, multisig.required_signatures());
        } else {
            msg!("No active add admin proposal");
        }
        
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
        
        msg!("Withdrawal proposal details:");
        msg!("  Proposal ID: {}", proposal.proposal_id);
        msg!("  Multisig account: {:?}", proposal.multisig);
        msg!("  Proposer: {:?}", proposal.proposer);
        msg!("  Destination: {:?}", proposal.destination);
        msg!("  Amount: {} lamports", proposal.amount);
        msg!("  Description: {}", proposal.description);
        msg!("  Executed: {}", proposal.executed);
        msg!("  Signatures: {}", proposal.signature_count);
        
        msg!("  Signers:");
        for i in 0..proposal.signature_count as usize {
            msg!("    Signer {}: {:?}", i + 1, proposal.signers[i]);
        }
        
        Ok(())
    }
    
    pub fn get_admin_proposals(ctx: Context<GetAdminProposals>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        
        if multisig.add_admin_candidate != Pubkey::default() {
            msg!("Active add admin proposal found:");
            msg!("  Candidate to add: {:?}", multisig.add_admin_candidate);
            msg!("  Signatures: {}/{} required", 
                multisig.add_admin_signatures, 
                multisig.required_signatures());
            
            msg!("  Signers:");
            for i in 0..multisig.add_admin_signatures as usize {
                msg!("    Signer {}: {:?}", i + 1, multisig.add_admin_signers[i]);
            }
        } else {
            msg!("No active add admin proposal");
        }
        
        if multisig.remove_admin_candidate != Pubkey::default() {
            msg!("Active remove admin proposal found:");
            msg!("  Admin to remove: {:?}", multisig.remove_admin_candidate);
            msg!("  Signatures: {}/{} required", 
                multisig.remove_admin_signatures, 
                multisig.required_signatures());
            
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

#[account]
pub struct Multisig {
    pub admins: [Pubkey; 10],
    pub admin_count: u8,
    pub add_admin_signers: [Pubkey; 10],
    pub add_admin_signatures: u8,
    pub add_admin_candidate: Pubkey,
    pub remove_admin_signers: [Pubkey; 10],
    pub remove_admin_signatures: u8,
    pub remove_admin_candidate: Pubkey,
    pub proposal_counter: u64,
}

#[account]
pub struct WithdrawalProposal {
    pub multisig: Pubkey,
    pub proposal_id: u64,
    pub proposer: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
    pub description: String,
    pub executed: bool,
    pub signers: [Pubkey; 10],
    pub signature_count: u8,
}

impl Multisig {
    pub fn is_admin(&self, pubkey: &Pubkey) -> bool {
        for i in 0..self.admin_count as usize {
            if self.admins[i] == *pubkey {
                return true;
            }
        }
        false
    }
    
    pub fn required_signatures(&self) -> u8 {
        if self.admin_count == 1 {
            1
        } else {
            self.admin_count
                .checked_div(2)
                .and_then(|half| half.checked_add(1))
                .unwrap_or(1)
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
        space = 8 + 32 * 10 + 1 + 32 * 10 + 1 + 32 + 32 * 10 + 1 + 32 + 8
    )]
    pub multisig: Account<'info, Multisig>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IsAdmin<'info> {
    #[account(
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetMultisigPubkey<'info> {
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct ProposeAddAdmin<'info> {
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
    pub signer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&signer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct ProposeWithdrawal<'info> {
    #[account(mut)]
    pub proposer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.is_admin(&proposer.key()) @ ErrorCode::NotAdmin,
        constraint = multisig.admin_count > 0
    )]
    pub multisig: Account<'info, Multisig>,
    
    /// CHECK: This is not being read from or written to
    pub destination: UncheckedAccount<'info>,
    
    #[account(
        init,
        payer = proposer,
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
    pub signer: Signer<'info>,
    
    #[account(
        mut,
        constraint = multisig.key() == proposal.multisig @ ErrorCode::InvalidProposal,
        constraint = multisig.is_admin(&signer.key()) @ ErrorCode::NotAdmin
    )]
    pub multisig: Account<'info, Multisig>,
    
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
    #[account(mut)]
    pub proposer: Signer<'info>,
    
    #[account(
        constraint = multisig.key() == proposal.multisig @ ErrorCode::InvalidProposal,
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
    
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
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetProposalDetails<'info> {
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
    
    #[account(
        constraint = proposal.multisig == multisig.key() @ ErrorCode::InvalidProposal,
        constraint = proposal.proposal_id > 0 @ ErrorCode::AccountNotInitialized,
        constraint = proposal.proposer != Pubkey::default() @ ErrorCode::AccountNotInitialized
    )]
    pub proposal: Account<'info, WithdrawalProposal>,
}

#[derive(Accounts)]
pub struct GetAdminProposals<'info> {
    #[account(
        constraint = multisig.admin_count > 0 @ ErrorCode::AccountNotInitialized
    )]
    pub multisig: Account<'info, Multisig>,
}

#[derive(Accounts)]
pub struct GetProposalCount<'info> {
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
