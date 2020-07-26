<i><b>
```diff
@@ All the updates will be soon @@
```
</b></i>

## Updated MemoryRanger: Hijacking Is Not An Option 
Updated MemoryRanger prevents the following new attacks:
* <b>Hijacking of NTFS structures</b> gains an unauthorized access to files opened without shared access by patching Stream Control Block structures; 
* <b>Handle Hijacking Attack</b> provides illegal access to exclusively open files via patching handle table entries;
* <b>Token Hijacking Attack</b> is designed to elevate the process privileges without using token-swapping technique;

News:
* Demos with Handle Hijacking and Token Hijacking as well as their prevention on newest <b>Windows 10 1903</b> are below.
* Demos with Hijacking of NTFS structures will be soon. 
* Updated MemoryRanger implements <b>special memory enclave to protect the sensitive kernel data</b>, e.g. Token Structures, from being tampered with all drivers, the scheme is below.

<img src="https://github.com/IgorKorkin/MemoryRanger/blob/master/memoryranger_prevents_token_and_handle_hijacking.png" width="1000" />

Handle Hijacking Attack and its Preventing are here:

[![Handle Hijacking Attack](https://img.youtube.com/vi/lLIR5u8AzAY/mqdefault.jpg)](https://www.youtube.com/watch?v=lLIR5u8AzAY&vq=hd1440&index=1&list=PL0Aerbf3kwUKsNCeJ7wSG957BrIOweEz_) [![The Prevention of Handle Hijacking](https://img.youtube.com/vi/ZivkK9x-Hew/mqdefault.jpg)](https://www.youtube.com/watch?v=ZivkK9x-Hew&vq=hd1440&index=2&list=PL0Aerbf3kwUKsNCeJ7wSG957BrIOweEz_)

Token Hijacking Attack and its Preventing are here:

[![Handle Hijacking Attack](https://img.youtube.com/vi/pnzvgGanbtw/mqdefault.jpg)](https://www.youtube.com/watch?v=pnzvgGanbtw&vq=hd1440&index=3&list=PL0Aerbf3kwUKsNCeJ7wSG957BrIOweEz_) [![The Prevention of Handle Hijacking](https://img.youtube.com/vi/mSh2R8WMYz8/mqdefault.jpg)](https://www.youtube.com/watch?v=mSh2R8WMYz8&vq=hd1440&index=4&list=PL0Aerbf3kwUKsNCeJ7wSG957BrIOweEz_)

# MemoryRanger

MemoryRanger hypervisor moves newly loaded drivers into isolated kernel spaces by using VT-x and EPT. MemoryRanger has been presented at Black Hat Europe 2018 and CDFSL 2019. 
MemoryRanger runs driver inside separate enclaves to protect the following kernel-mode areas: 
- allocated data, drivers code, and EPROCESS.token fields (BlackHat 2018);
- FILE_OBJECT structures (CDFSL 2019).

## MemoryRanger at the CDFSL 2019:
<img src="https://github.com/IgorKorkin/MemoryRanger/blob/master/cdfsl2019_memoryranger_prevents_fileobj_hijacking.png" width="700" />

 * demonstration of illegal access to an exclusive open file via FILE_OBJECT hijacking;
 * prevention of FILE_OBJECT hijacking;
 * paper, slides, demos are [here](https://igorkorkin.blogspot.com/2019/04/memoryranger-prevents-hijacking.html).
 
[![The Hijacking Attack](https://img.youtube.com/vi/2mU85RluOSA/mqdefault.jpg)](https://www.youtube.com/watch?v=2mU85RluOSA&index=1&list=PL0Aerbf3kwUKlHszFlcIFivmslRl4xmhB) [![The Attack Prevention](https://img.youtube.com/vi/8ONmC5Do4I4/mqdefault.jpg)](https://www.youtube.com/watch?v=8ONmC5Do4I4&index=2&list=PL0Aerbf3kwUKlHszFlcIFivmslRl4xmhB)
 
## MemoryRanger at the Black Hat Europe 2018
![alt text](https://github.com/IgorKorkin/MemoryRanger/blob/master/before_and_after_memoryranger.png)
 * demonstration of illegal access to allocated data, drivers code, and EPROCESS.token field;
 * protection of the dynamically allocated data;
 * preventing newly loaded drivers to escalate process priviledges; 
 * paper, slides, demos are [here](https://igorkorkin.blogspot.com/2018/12/divide-et-impera-memoryranger-runs.html).
 
 [![The Attack](https://img.youtube.com/vi/HNxc-tjy3QA/mqdefault.jpg)](https://www.youtube.com/watch?v=HNxc-tjy3QA&index=1&list=PL0Aerbf3kwULpVhoHyjMUeUFLwnvur5iu) [![The Attack Prevention](https://img.youtube.com/vi/vrm9cgn5DsU/mqdefault.jpg)](https://www.youtube.com/watch?v=vrm9cgn5DsU&index=2&list=PL0Aerbf3kwULpVhoHyjMUeUFLwnvur5iu)


## Details
MemoryRanger hypervisor is based on these projects:
- [MemoryMonRWX](https://github.com/tandasat/MemoryMon/tree/rwe_cdfs) by [Satoshi Tanda](https://twitter.com/standa_t);
- [DdiMon](https://github.com/tandasat/DdiMon) by [Satoshi Tanda](https://twitter.com/standa_t);
- [AllMemPro](https://github.com/IgorKorkin/AllMemPro).
