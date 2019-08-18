#pragma once

#include "common.h"
#include "..\shared\mem_attacker_shared.h" // IOCTL-codes
#include "vulnerable_code.h"
#include "..\..\utils\zwfile.h"
#include "mem_attacker_driver.h"

extern "C" namespace token_hijacking {

	typedef struct _TOKEN_SOURCE
	{
		CHAR SourceName[8];
		LUID SourceIdentifier;
	} TOKEN_SOURCE, *PTOKEN_SOURCE;


	typedef struct _SEP_TOKEN_PRIVILEGES
	{
		UINT64 Present;
		UINT64 Enabled;
		UINT64 EnabledByDefault;
	} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;


	typedef struct _SEP_AUDIT_POLICY
	{
		TOKEN_AUDIT_POLICY AdtTokenPolicy;
		UCHAR PolicySetStatus;
	} SEP_AUDIT_POLICY, *PSEP_AUDIT_POLICY;


	typedef enum _PROXY_CLASS
	{
		ProxyFull = 0,
		ProxyService = 1,
		ProxyTree = 2,
		ProxyDirectory = 3
	} PROXY_CLASS;


	typedef struct _SECURITY_TOKEN_PROXY_DATA
	{
		ULONG Length;
		PROXY_CLASS ProxyClass;
		UNICODE_STRING PathInfo;
		ULONG ContainerMask;
		ULONG ObjectMask;
	} SECURITY_TOKEN_PROXY_DATA, *PSECURITY_TOKEN_PROXY_DATA;


	typedef struct _SECURITY_TOKEN_AUDIT_DATA
	{
		ULONG Length;
		ULONG GrantMask;
		ULONG DenyMask;
	} SECURITY_TOKEN_AUDIT_DATA, *PSECURITY_TOKEN_AUDIT_DATA;


	typedef struct _SEP_LOGON_SESSION_REFERENCES
	{
		_SEP_LOGON_SESSION_REFERENCES* Next;
		LUID LogonId;
		LUID BuddyLogonId;
		ULONG ReferenceCount;
		ULONG Flags;
		PVOID /*PDEVICE_MAP*/ pDeviceMap;
		PVOID Token;
		UNICODE_STRING AccountName;
		UNICODE_STRING AuthorityName;
	} SEP_LOGON_SESSION_REFERENCES, *PSEP_LOGON_SESSION_REFERENCES;

	typedef struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
	{
		ULONG SecurityAttributeCount; /* : Uint4B*/
		LIST_ENTRY SecurityAttributesList;/* : _LIST_ENTRY*/
		ULONG WorkingSecurityAttributeCount;/* : Uint4B*/
		LIST_ENTRY WorkingSecurityAttributesList;/* : _LIST_ENTRY*/
	}AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION, *PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION;

	typedef struct _TOKEN
	{
		TOKEN_SOURCE TokenSource;				// +0x000 TokenSource      : _TOKEN_SOURCE
		LUID TokenId;							// +0x010 TokenId          : _LUID
		LUID AuthenticationId;					// +0x018 AuthenticationId : _LUID
		LUID ParentTokenId;						// +0x020 ParentTokenId    : _LUID
		LARGE_INTEGER ExpirationTime;			// +0x028 ExpirationTime   : _LARGE_INTEGER
		PERESOURCE TokenLock;					// +0x030 TokenLock        : Ptr64 _ERESOURCE
		LUID ModifiedId;						// +0x038 ModifiedId       : _LUID
		SEP_TOKEN_PRIVILEGES Privileges;		// +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
		SEP_AUDIT_POLICY AuditPolicy;			// +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
		ULONG SessionId;						// +0x078 SessionId        : Uint4B
		ULONG UserAndGroupCount;				// +0x07c UserAndGroupCount : Uint4B
		ULONG RestrictedSidCount;				// +0x080 RestrictedSidCount : Uint4B
		ULONG VariableLength;					// +0x084 VariableLength   : Uint4B
		ULONG DynamicCharged;					// +0x088 DynamicCharged   : Uint4B
		ULONG DynamicAvailable;					// +0x08c DynamicAvailable : Uint4B
		ULONG DefaultOwnerIndex;				// +0x090 DefaultOwnerIndex : Uint4B
		PSID_AND_ATTRIBUTES UserAndGroups;		// +0x098 UserAndGroups    : Ptr64 _SID_AND_ATTRIBUTES
		PSID_AND_ATTRIBUTES RestrictedSids;		// +0x0a0 RestrictedSids   : Ptr64 _SID_AND_ATTRIBUTES
		PVOID PrimaryGroup;						// +0x0a8 PrimaryGroup     : Ptr64 Void
		ULONG * DynamicPart;					// +0x0b0 DynamicPart      : Ptr64 Uint4B
		PACL DefaultDacl;						// +0x0b8 DefaultDacl      : Ptr64 _ACL
		TOKEN_TYPE TokenType;					// +0x0c0 TokenType        : _TOKEN_TYPE

		SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;

		ULONG TokenFlags;													//  Uint4B
		UCHAR TokenInUse;													//  UChar
		ULONG IntegrityLevelIndex;											//  Uint4B
		ULONG MandatoryPolicy;												//  Uint4B
		PSEP_LOGON_SESSION_REFERENCES LogonSession;							//  Ptr64 to struct _SEP_LOGON_SESSION_REFERENCES, 17 elements, 0xc0 bytes
		LUID OriginatingLogonSession;										//  struct _LUID, 2 elements, 0x8 bytes
		SID_AND_ATTRIBUTES_HASH SidHash;									//  struct _SID_AND_ATTRIBUTES_HASH, 3 elements, 0x110 bytes
		SID_AND_ATTRIBUTES_HASH RestrictedSidHash;							//  struct _SID_AND_ATTRIBUTES_HASH, 3 elements, 0x110 bytes
		PAUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION pSecurityAttributes;	//  Ptr64 to struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION, 4 elements, 0x30 bytes
		PVOID Package;														//  Ptr64 to Void
		PSID_AND_ATTRIBUTES Capabilities;									//  Ptr64 to struct _SID_AND_ATTRIBUTES, 2 elements, 0x10 bytes
		ULONG CapabilityCount;												//  Uint4B
		SID_AND_ATTRIBUTES_HASH CapabilitiesHash;							//  struct _SID_AND_ATTRIBUTES_HASH, 3 elements, 0x110 bytes
		PVOID LowboxNumberEntry;											//  Ptr64 to struct _SEP_LOWBOX_NUMBER_ENTRY, 5 elements, 0x38 bytes
		PVOID LowboxHandlesEntry;											//  Ptr64 to struct _SEP_LOWBOX_HANDLES_ENTRY, 5 elements, 0x38 bytes
		PVOID pClaimAttributes;												//  Ptr64 to struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION, 10 elements, 0x260 bytes
		PVOID TrustLevelSid;												//  Ptr64 to Void
		_TOKEN* TrustLinkedToken;											//  Ptr64 to struct _TOKEN, 46 elements, 0x488 bytes
		PVOID IntegrityLevelSidValue;										//  Ptr64 to Void
		PVOID TokenSidValues;												//  Ptr64 to struct _SEP_SID_VALUES_BLOCK, 4 elements, 0x20 bytes
		PVOID IndexEntry;													//  Ptr64 to struct _SEP_LUID_TO_INDEX_MAP_ENTRY, 5 elements, 0x38 bytes
		PVOID DiagnosticInfo;												//  Ptr64 to struct _SEP_TOKEN_DIAG_TRACK_ENTRY, 7 elements, 0x120 bytes
		ULONG64 VariablePart;												//  Uint8B
	} TOKEN, *PTOKEN;

	//////////////////////////////////////////////////////////////////////////

	bool hijacking(const DWORD targetPID);
	bool hijacking2(const DWORD targetPID);
}