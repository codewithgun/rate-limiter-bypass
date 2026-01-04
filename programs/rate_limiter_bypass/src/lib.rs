#![cfg_attr(target_arch = "bpf", no_std)]
use const_crypto::ed25519;
use pinocchio::{
    account_info::AccountInfo,
    cpi::{invoke, invoke_signed},
    instruction::{AccountMeta, Instruction, Signer},
    msg, program_entrypoint,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_pubkey::declare_id;

program_entrypoint!(process_instruction);

declare_id!("5C61rHvq6uvAUs5Sw68SHNueFZknUiAUGyRkkqmU6DBC");

const DAMM_V2_PROGRAM_ID: Pubkey =
    pinocchio_pubkey::from_str("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");

// Discriminator + SwapParameters
const SWAP_PARAM_LEN: usize = 8 + 16;
const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

// DammV2 swap account without remaining accounts
const DAMM_V2_SWAP_ACC_LEN: usize = 14;
const ACC_LEN: usize = DAMM_V2_SWAP_ACC_LEN + 2; // +2 = Authority + Sysvar

const AUTHORITY_AND_BUMP: ([u8; 32], u8) =
    ed25519::derive_program_address(&[b"authority"], &crate::ID);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &crate::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (discriminator, instruction_data) = instruction_data.split_first().unwrap();

    match discriminator {
        0 => {
            msg!("Single direct swap");
            direct_swap(accounts, instruction_data)?;
        }
        1 => {
            msg!("Multiple direct CPI swaps");
            direct_swap(accounts, instruction_data)?;
            direct_swap(accounts, instruction_data)?;
        }
        2 => {
            msg!("Direct swap");
            let (_authority_account, remaining_accounts) = accounts.split_first().unwrap();
            direct_swap(remaining_accounts, instruction_data)?;

            msg!("Self CPI swap (nested)");
            nest_cpi_swap(accounts, instruction_data)?;
        }
        3 => {
            msg!("Inside nest cpi swap invoke self and then direct swap");
            // Nest cpi swap invoke self and then direct swap
            let (maybe_authority_acc, remaining_accounts) = accounts.split_first().unwrap();

            if maybe_authority_acc.key() != &AUTHORITY_AND_BUMP.0 {
                return Err(ProgramError::IncorrectAuthority);
            }

            if !maybe_authority_acc.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            direct_swap(remaining_accounts, instruction_data)?;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    Ok(())
}

fn nest_cpi_swap(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let acc_infos: [&AccountInfo; ACC_LEN] = [
        &accounts[0],
        &accounts[1],
        &accounts[2],
        &accounts[3],
        &accounts[4],
        &accounts[5],
        &accounts[6],
        &accounts[7],
        &accounts[8],
        &accounts[9],
        &accounts[10],
        &accounts[11],
        &accounts[12],
        &accounts[13],
        &accounts[14],
        &accounts[15],
    ];

    let discriminator = instruction_data
        .get(..8)
        .ok_or(ProgramError::InvalidInstructionData)?;

    if discriminator != SWAP_DISCRIMINATOR {
        return Err(ProgramError::InvalidInstructionData);
    }

    if instruction_data.len() != SWAP_PARAM_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let nest_cpi_discriminator = 3;
    let mut data = [0u8; SWAP_PARAM_LEN + 1];
    data[0] = nest_cpi_discriminator;
    data[1..].copy_from_slice(instruction_data);

    let acc_metas = acc_infos
        .iter()
        .map(|acc| {
            if acc.key() == &AUTHORITY_AND_BUMP.0 {
                AccountMeta {
                    pubkey: acc.key(),
                    is_signer: true,
                    is_writable: acc.is_writable(),
                }
            } else {
                AccountMeta {
                    pubkey: acc.key(),
                    is_signer: acc.is_signer(),
                    is_writable: acc.is_writable(),
                }
            }
        })
        .collect::<Vec<_>>();

    let ix = Instruction {
        program_id: &crate::ID,
        accounts: acc_metas.as_ref(),
        data: &data,
    };

    let seeds = pinocchio::seeds!(b"authority", &[AUTHORITY_AND_BUMP.1]);
    let signers_seeds = [Signer::from(&seeds)];

    invoke_signed(&ix, &acc_infos, &signers_seeds)?;

    Ok(())
}

fn direct_swap(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let (accounts, _remaining_accounts) = accounts.split_at(DAMM_V2_SWAP_ACC_LEN + 1);

    let acc_infos: [&AccountInfo; DAMM_V2_SWAP_ACC_LEN + 1] = [
        &accounts[0],
        &accounts[1],
        &accounts[2],
        &accounts[3],
        &accounts[4],
        &accounts[5],
        &accounts[6],
        &accounts[7],
        &accounts[8],
        &accounts[9],
        &accounts[10],
        &accounts[11],
        &accounts[12],
        &accounts[13],
        &accounts[14],
    ];

    let acc_metas = acc_infos
        .iter()
        .map(|acc| AccountMeta {
            pubkey: acc.key(),
            is_signer: acc.is_signer(),
            is_writable: acc.is_writable(),
        })
        .collect::<Vec<_>>();

    let ix = Instruction {
        program_id: &DAMM_V2_PROGRAM_ID,
        accounts: acc_metas.as_ref(),
        data: instruction_data,
    };

    invoke(&ix, &acc_infos)?;

    Ok(())
}
