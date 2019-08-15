## Updated MemoryRanger for the Black Hat Europe 2019 
<img src="https://github.com/IgorKorkin/MemoryRanger/blob/master/blackhat2019_memoryranger_prevents_token_and_handle_hijacking.png" width="1000" />

* Handle Hijacking: illegal access to exclusive open files via patching handle table entries;
* Token Hijacking: elevation of process privileges without using token-swapping technique;
* Updated Memory Ranger can prevent Token Hijacking and Handle Hijacking attacks.

-->>>> Four new demos with updated MemoryRanger for the BHEU 2019 will be uploaded soon.<<<<--

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
