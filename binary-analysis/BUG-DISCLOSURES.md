# Bug Disclosures — All Analyzed Binaries 
**Generated:** 2026-07-06 
**Methodology:** Ghidra headless → VigilExportSummary.java → risky-import detection 
--- 
## Summary 
| Stat | Count |
|------|-------|
| Binaries analyzed | 809 |
| With exploitable surfaces | 573 |
| Total risky import functions | 3815 |
| Total functions reversed | 544877 | 
--- 
## OpenAI-Specific Disclosures 
### openai-numpy-_common 
**Binary:** numpy-_common.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 362 | **Risky:** 95 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_SetItem | 00104030 | undefined PyObject_SetItem(void) | general |
| PyObject_Init | 00104050 | undefined PyObject_Init(void) | general |
| PyObject_Format | 001040b0 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 001040e0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyObject_GetAttrString | 00104140 | undefined PyObject_GetAttrString(void) | general |
| PyObject_SetAttrString | 00104160 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00104170 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 00104180 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_SetObject | 001041b0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001041c0 | undefined PyObject_GC_Del(void) | general |
| PyErr_NormalizeException | 001041d0 | undefined PyErr_NormalizeException(void) | general |
| PyObject_RichCompare | 00104210 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00104250 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 00104280 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 00104290 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 001042a0 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 001042c0 | undefined PyObject_GetItem(void) | general |
| PyErr_SetNone | 00104300 | undefined PyErr_SetNone(void) | general |
| PyErr_ExceptionMatches | 00104310 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00104340 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001043b0 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001043d0 | undefined PyErr_Clear(void) | general |
| PyObject_CallFunction | 00104400 | undefined PyObject_CallFunction(void) | general |
| memcpy | 00104430 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyArg_UnpackTuple | 00104450 | undefined PyArg_UnpackTuple(void) | general |
| PyObject_SetAttr | 00104460 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00104470 | undefined PyErr_Occurred(void) | general |
| PyObject_CallObject | 001044b0 | undefined PyObject_CallObject(void) | general |
| PyObject_VectorcallDict | 001044d0 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 001044e0 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 00104510 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 00104530 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00104570 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 001045b0 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 001045e0 | undefined PyObject_VectorcallMethod(void) | general |
| PyObject_GetIter | 00104630 | undefined PyObject_GetIter(void) | general |
| PyObject_IsSubclass | 00104690 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 001046a0 | undefined PyObject_Call(void) | general |
| PyErr_Format | 001046d0 | undefined PyErr_Format(void) | general |
| PyObject_GetAttr | 00104750 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00104760 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 001047b0 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 001047c0 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 00104830 | undefined PyObject_GC_UnTrack(void) | general |
| PyErr_WriteUnraisable | 00104840 | undefined PyErr_WriteUnraisable(void) | general |
| __Pyx_PyObject_GetAttrStr | 00107830 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| __Pyx_PyObject_Call.constprop.0 | 00108020 | undefined __Pyx_PyObject_Call.constprop.0(void) | general |
| __Pyx_PyErr_GivenExceptionMatchesTuple | 001084b0 | undefined __Pyx_PyErr_GivenExceptionMatchesTuple(void) | general |
| __Pyx_PyErr_GivenExceptionMatches.part.0 | 00108670 | undefined __Pyx_PyErr_GivenExceptionMatches.part.0(void) | general |
| __Pyx_PyObject_FastCallDict.constprop.0 | 00109770 | undefined __Pyx_PyObject_FastCallDict.constprop.0(void) | general |
| PyObject_SetItem | 0013d000 | undefined PyObject_SetItem(void) | general |
| PyObject_Init | 0013d010 | undefined PyObject_Init(void) | general |
| PyObject_Format | 0013d070 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 0013d088 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyObject_GetAttrString | 0013d0b8 | undefined PyObject_GetAttrString(void) | general |
| PyObject_SetAttrString | 0013d0c8 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 0013d0d0 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 0013d0d8 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_SetObject | 0013d0f0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 0013d0f8 | undefined PyObject_GC_Del(void) | general |
| PyErr_NormalizeException | 0013d100 | undefined PyErr_NormalizeException(void) | general |
| PyObject_RichCompare | 0013d120 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 0013d140 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 0013d168 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 0013d170 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 0013d178 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 0013d188 | undefined PyObject_GetItem(void) | general |
| PyErr_SetNone | 0013d1c8 | undefined PyErr_SetNone(void) | general |
| PyErr_ExceptionMatches | 0013d1d0 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 0013d1f0 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 0013d228 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 0013d238 | undefined PyErr_Clear(void) | general |
| PyObject_CallFunction | 0013d260 | undefined PyObject_CallFunction(void) | general |
| memcpy | 0013d288 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyArg_UnpackTuple | 0013d2a0 | undefined PyArg_UnpackTuple(void) | general |
| PyObject_SetAttr | 0013d2a8 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 0013d2b0 | undefined PyErr_Occurred(void) | general |
| PyObject_CallObject | 0013d2d0 | undefined PyObject_CallObject(void) | general |
| PyObject_VectorcallDict | 0013d2e0 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 0013d2e8 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 0013d318 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 0013d328 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 0013d348 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 0013d370 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 0013d390 | undefined PyObject_VectorcallMethod(void) | general |
| PyObject_GetIter | 0013d3d0 | undefined PyObject_GetIter(void) | general |
| PyObject_IsSubclass | 0013d410 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 0013d420 | undefined PyObject_Call(void) | general |
| PyErr_Format | 0013d448 | undefined PyErr_Format(void) | general |
| PyObject_GetAttr | 0013d498 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 0013d4a0 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 0013d4d0 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 0013d4d8 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 0013d510 | undefined PyObject_GC_UnTrack(void) | general |
| PyErr_WriteUnraisable | 0013d520 | undefined PyErr_WriteUnraisable(void) | general |

### openai-numpy-_mt19937 
**Binary:** numpy-_mt19937.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 347 | **Risky:** 99 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_SetItem | 00104040 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00104060 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 001040b0 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 001040c0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00104100 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 00104120 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 00104130 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 00104150 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00104160 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 00104170 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_NoMemory | 001041a0 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 001041b0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 001041c0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001041d0 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 001041f0 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00104200 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00104230 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 00104270 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 00104280 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 001042a0 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 001042c0 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 00104310 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00104340 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001043b0 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001043c0 | undefined PyErr_Clear(void) | general |
| memcpy | 00104420 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 00104440 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00104450 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 001044a0 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 001044c0 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyMem_RawFree | 001044e0 | undefined PyMem_RawFree(void) | memory-corruption |
| PyObject_Size | 001044f0 | undefined PyObject_Size(void) | general |
| PyObject_Vectorcall | 00104510 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 00104520 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00104550 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 00104590 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 001045e0 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00104600 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 00104660 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 00104680 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 00104690 | undefined PyObject_Call(void) | general |
| PyErr_Format | 001046b0 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 001046f0 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00104720 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00104730 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00104770 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 00104780 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 001047d0 | undefined PyObject_GC_UnTrack(void) | general |
| __Pyx_PyObject_GetAttrStr | 001073e0 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| __Pyx_PyErr_GivenExceptionMatchesTuple | 00108480 | undefined __Pyx_PyErr_GivenExceptionMatchesTuple(void) | general |
| __Pyx_PyObject_FastCallDict.constprop.0 | 00109780 | undefined __Pyx_PyObject_FastCallDict.constprop.0(void) | general |
| PyObject_SetItem | 0011e008 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 0011e020 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 0011e070 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 0011e078 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 0011e098 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 0011e0a8 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 0011e0b0 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 0011e0c0 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 0011e0c8 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 0011e0d0 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_NoMemory | 0011e0e8 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 0011e0f0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 0011e0f8 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 0011e100 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 0011e110 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 0011e118 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 0011e130 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 0011e158 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 0011e160 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 0011e170 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 0011e180 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 0011e1c8 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 0011e1e0 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 0011e218 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 0011e220 | undefined PyErr_Clear(void) | general |
| memcpy | 0011e270 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 0011e288 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 0011e290 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 0011e2b8 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 0011e2c8 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyMem_RawFree | 0011e2d8 | undefined PyMem_RawFree(void) | memory-corruption |
| PyObject_Size | 0011e2e8 | undefined PyObject_Size(void) | general |
| PyObject_Vectorcall | 0011e308 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 0011e310 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 0011e328 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 0011e350 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 0011e390 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 0011e3b0 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 0011e3e8 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 0011e400 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 0011e410 | undefined PyObject_Call(void) | general |
| PyErr_Format | 0011e428 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 0011e450 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 0011e470 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 0011e478 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 0011e4a0 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 0011e4a8 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 0011e4d0 | undefined PyObject_GC_UnTrack(void) | general |

### openai-numpy-_pcg64 
**Binary:** numpy-_pcg64.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 359 | **Risky:** 89 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_SetItem | 00104040 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00104060 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 001040b0 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 001040c0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00104100 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 00104140 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 00104150 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 00104170 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00104180 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 001041b0 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 001041c0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 001041d0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001041e0 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 00104210 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00104220 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00104260 | undefined PyObject_GC_Track(void) | general |
| PyErr_SetString | 001042a0 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 001042c0 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 001042d0 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 00104320 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00104350 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001043b0 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001043d0 | undefined PyErr_Clear(void) | general |
| memcpy | 00104430 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 00104470 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00104480 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 001044d0 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 001044f0 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 00104520 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 00104530 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00104560 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 001045a0 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 001045f0 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00104610 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 00104660 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 00104680 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 00104690 | undefined PyObject_Call(void) | general |
| PyErr_Format | 001046b0 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 001046f0 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00104700 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00104710 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00104760 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 00104770 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 001047c0 | undefined PyObject_GC_UnTrack(void) | general |
| __Pyx_PyObject_GetAttrStr | 00107ba0 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| PyObject_SetItem | 00121008 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00121020 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 00121070 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 00121078 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00121098 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 001210b8 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 001210c0 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 001210d0 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 001210d8 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 001210f0 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 001210f8 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 00121100 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 00121108 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 00121120 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00121128 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00121148 | undefined PyObject_GC_Track(void) | general |
| PyErr_SetString | 00121170 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 00121180 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 00121188 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 001211c8 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 001211e0 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 00121210 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 00121220 | undefined PyErr_Clear(void) | general |
| memcpy | 00121270 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 00121298 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 001212a0 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 001212c8 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 001212d8 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 00121308 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 00121310 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00121328 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 00121350 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00121390 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 001213b0 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 001213e0 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 001213f8 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 00121408 | undefined PyObject_Call(void) | general |
| PyErr_Format | 00121420 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 00121448 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00121458 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00121460 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00121490 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 00121498 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 001214c0 | undefined PyObject_GC_UnTrack(void) | general |

### openai-numpy-_philox 
**Binary:** numpy-_philox.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 339 | **Risky:** 92 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_SetItem | 00104040 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00104060 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 001040b0 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 001040c0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00104100 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 00104130 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 00104140 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 00104160 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00104170 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 001041a0 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 001041b0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 001041c0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001041d0 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 00104200 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00104210 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00104250 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 00104290 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 001042a0 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 001042c0 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 001042e0 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 00104340 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00104370 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001043d0 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001043f0 | undefined PyErr_Clear(void) | general |
| memcpy | 00104450 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 00104480 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00104490 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 001044e0 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 00104500 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 00104530 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 00104540 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00104570 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 001045b0 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00104600 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00104630 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 00104680 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 001046a0 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 001046b0 | undefined PyObject_Call(void) | general |
| PyErr_Format | 001046d0 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 00104710 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00104720 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00104730 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00104780 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 00104790 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 001047e0 | undefined PyObject_GC_UnTrack(void) | general |
| __Pyx_PyErr_GivenExceptionMatches.part.0 | 00104dfe | undefined __Pyx_PyErr_GivenExceptionMatches.part.0(void) | general |
| __Pyx_PyObject_GetAttrStr | 001077e0 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| PyObject_SetItem | 0011b008 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 0011b020 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 0011b070 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 0011b078 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 0011b098 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 0011b0b0 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 0011b0b8 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 0011b0c8 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 0011b0d0 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 0011b0e8 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 0011b0f0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 0011b0f8 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 0011b100 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 0011b118 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 0011b120 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 0011b140 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 0011b168 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 0011b170 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 0011b180 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 0011b190 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 0011b1e0 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 0011b1f8 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 0011b228 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 0011b238 | undefined PyErr_Clear(void) | general |
| memcpy | 0011b288 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 0011b2a8 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 0011b2b0 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 0011b2d8 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 0011b2e8 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 0011b318 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 0011b320 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 0011b338 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 0011b360 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 0011b3a0 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 0011b3c8 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 0011b3f8 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 0011b410 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 0011b420 | undefined PyObject_Call(void) | general |
| PyErr_Format | 0011b438 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 0011b460 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 0011b470 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 0011b478 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 0011b4a8 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 0011b4b0 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 0011b4d8 | undefined PyObject_GC_UnTrack(void) | general |

### openai-numpy-_sfc64 
**Binary:** numpy-_sfc64.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 309 | **Risky:** 83 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_VisitManagedDict | 00104050 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_ClearWeakRefs | 001040a0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 001040e0 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 00104110 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 00104120 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 00104140 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00104150 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 00104180 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 00104190 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 001041a0 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001041b0 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 001041d0 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 001041e0 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00104220 | undefined PyObject_GC_Track(void) | general |
| PyErr_SetString | 00104240 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 00104260 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 00104270 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 001042c0 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 001042f0 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 00104340 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 00104360 | undefined PyErr_Clear(void) | general |
| PyObject_SetAttr | 001043e0 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 001043f0 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 00104440 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 00104460 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 00104490 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 001044a0 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 001044d0 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 00104510 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00104560 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00104580 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 001045d0 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 001045f0 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 00104600 | undefined PyObject_Call(void) | general |
| PyErr_Format | 00104620 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 00104670 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00104680 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00104690 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 001046d0 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 001046e0 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 00104720 | undefined PyObject_GC_UnTrack(void) | general |
| __Pyx_PyObject_GetAttrStr | 00107490 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| PyObject_VisitManagedDict | 00114018 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_ClearWeakRefs | 00114058 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00114078 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 00114090 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 00114098 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 001140a8 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 001140b0 | undefined PyErr_WarnEx(void) | general |
| PyErr_NoMemory | 001140c8 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 001140d0 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 001140d8 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 001140e0 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 001140f0 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 001140f8 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00114118 | undefined PyObject_GC_Track(void) | general |
| PyErr_SetString | 00114130 | undefined PyErr_SetString(void) | general |
| _PyObject_GC_New | 00114140 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 00114148 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 00114188 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 001141a0 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001141c8 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001141d8 | undefined PyErr_Clear(void) | general |
| PyObject_SetAttr | 00114240 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00114248 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 00114270 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 00114280 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Vectorcall | 001142b0 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 001142b8 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 001142d0 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 001142f8 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00114338 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00114358 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_HasAttr | 00114388 | undefined PyObject_HasAttr(void) | general |
| PyObject_IsSubclass | 001143a0 | undefined PyObject_IsSubclass(void) | general |
| PyObject_Call | 001143b0 | undefined PyObject_Call(void) | general |
| PyErr_Format | 001143c8 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 001143f8 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00114408 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00114410 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00114438 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 00114440 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 00114460 | undefined PyObject_GC_UnTrack(void) | general |

### openai-numpy-mtrand 
**Binary:** numpy-mtrand.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 599 | **Risky:** 106 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| PyObject_SetItem | 00107050 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00107070 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 001070c0 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 001070e0 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 00107130 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 001071a0 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 001071b0 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 001071d0 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 001071e0 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 001071f0 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_NoMemory | 00107220 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 00107230 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 00107240 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 00107250 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 00107280 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00107290 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 001072d0 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 00107310 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 00107320 | undefined PyErr_SetString(void) | general |
| PyObject_IsInstance | 00107330 | undefined PyObject_IsInstance(void) | general |
| _PyObject_GC_New | 00107350 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 00107370 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 001073e0 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00107450 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 00107510 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 00107530 | undefined PyErr_Clear(void) | general |
| memcpy | 00107590 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 001075e0 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 001075f0 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 00107640 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 00107660 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Size | 00107680 | undefined PyObject_Size(void) | general |
| PyObject_Vectorcall | 001076a0 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 001076c0 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 001076f0 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 00107730 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00107780 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 001077a0 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_GetIter | 001077c0 | undefined PyObject_GetIter(void) | general |
| PyObject_HasAttr | 00107810 | undefined PyObject_HasAttr(void) | general |
| PyObject_Call | 00107860 | undefined PyObject_Call(void) | general |
| PyErr_Format | 00107880 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 001078d0 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00107910 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00107930 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 00107990 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 001079a0 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 00107a00 | undefined PyObject_GC_UnTrack(void) | general |
| __Pyx_PyObject_SetAttrStr | 001116a0 | undefined __Pyx_PyObject_SetAttrStr(void) | general |
| __Pyx_PyObject_Call | 001116c0 | undefined __Pyx_PyObject_Call(void) | general |
| __Pyx_PyObject_GetAttrStr | 00111c60 | undefined __Pyx_PyObject_GetAttrStr(void) | general |
| __Pyx__PyObject_LookupSpecial.constprop. | 001129f0 | undefined __Pyx__PyObject_LookupSpecial.constprop.0(void) | general |
| __Pyx_PyErr_GivenExceptionMatchesTuple | 00113d70 | undefined __Pyx_PyErr_GivenExceptionMatchesTuple(void) | general |
| __Pyx_PyErr_GivenExceptionMatches.part.0 | 001141d0 | undefined __Pyx_PyErr_GivenExceptionMatches.part.0(void) | general |
| __Pyx_PyObject_FastCallDict.constprop.0 | 00114f30 | undefined __Pyx_PyObject_FastCallDict.constprop.0(void) | general |
| __Pyx_PyObject_GetItem | 001150e0 | undefined __Pyx_PyObject_GetItem(void) | general |
| __Pyx_PyObject_GetSlice.constprop.0 | 00115530 | undefined __Pyx_PyObject_GetSlice.constprop.0(void) | buffer-overflow |
| __Pyx_PyObject_FastCallDict.constprop.1 | 00116090 | undefined __Pyx_PyObject_FastCallDict.constprop.1(void) | general |
| PyObject_SetItem | 00194010 | undefined PyObject_SetItem(void) | general |
| PyObject_VisitManagedDict | 00194028 | undefined PyObject_VisitManagedDict(void) | general |
| PyObject_Format | 00194070 | undefined PyObject_Format(void) | general |
| PyObject_ClearWeakRefs | 00194080 | undefined PyObject_ClearWeakRefs(void) | use-after-free |
| PyMem_Free | 001940a8 | undefined PyMem_Free(void) | memory-corruption |
| PyObject_GetAttrString | 001940e0 | undefined PyObject_GetAttrString(void) | general |
| PyObject_CallMethodObjArgs | 001940e8 | undefined PyObject_CallMethodObjArgs(void) | general |
| PyObject_SetAttrString | 001940f8 | undefined PyObject_SetAttrString(void) | general |
| PyErr_WarnEx | 00194100 | undefined PyErr_WarnEx(void) | general |
| PyObject_HasAttrWithError | 00194108 | undefined PyObject_HasAttrWithError(void) | general |
| PyErr_NoMemory | 00194120 | undefined PyErr_NoMemory(void) | general |
| PyObject_GenericGetDict | 00194128 | undefined PyObject_GenericGetDict(void) | general |
| PyErr_SetObject | 00194130 | undefined PyErr_SetObject(void) | general |
| PyObject_GC_Del | 00194138 | undefined PyObject_GC_Del(void) | general |
| PyArg_ValidateKeywordArguments | 00194150 | undefined PyArg_ValidateKeywordArguments(void) | general |
| PyObject_RichCompare | 00194158 | undefined PyObject_RichCompare(void) | general |
| PyObject_GC_Track | 00194178 | undefined PyObject_GC_Track(void) | general |
| PyErr_GivenExceptionMatches | 001941a0 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyErr_SetString | 001941a8 | undefined PyErr_SetString(void) | general |
| PyObject_IsInstance | 001941b8 | undefined PyObject_IsInstance(void) | general |
| _PyObject_GC_New | 001941c8 | undefined _PyObject_GC_New(void) | general |
| PyObject_GetItem | 001941d8 | undefined PyObject_GetItem(void) | general |
| PyErr_ExceptionMatches | 00194230 | undefined PyErr_ExceptionMatches(void) | general |
| PyObject_CallFinalizerFromDealloc | 00194268 | undefined PyObject_CallFinalizerFromDealloc(void) | general |
| PyObject_RichCompareBool | 001942c8 | undefined PyObject_RichCompareBool(void) | general |
| PyErr_Clear | 001942d8 | undefined PyErr_Clear(void) | general |
| memcpy | 00194328 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyObject_SetAttr | 00194358 | undefined PyObject_SetAttr(void) | general |
| PyErr_Occurred | 00194360 | undefined PyErr_Occurred(void) | general |
| PyObject_VectorcallDict | 00194390 | undefined PyObject_VectorcallDict(void) | general |
| PyObject_CallFunctionObjArgs | 001943a0 | undefined PyObject_CallFunctionObjArgs(void) | general |
| PyObject_Size | 001943b8 | undefined PyObject_Size(void) | general |
| PyObject_Vectorcall | 001943d8 | undefined PyObject_Vectorcall(void) | general |
| PyObject_IsTrue | 001943e8 | undefined PyObject_IsTrue(void) | general |
| PyObject_Hash | 00194400 | undefined PyObject_Hash(void) | general |
| PyObject_GC_IsFinalized | 00194430 | undefined PyObject_GC_IsFinalized(void) | general |
| PyObject_VectorcallMethod | 00194478 | undefined PyObject_VectorcallMethod(void) | general |
| _PyObject_GetDictPtr | 00194498 | undefined _PyObject_GetDictPtr(void) | general |
| PyObject_GetIter | 001944a8 | undefined PyObject_GetIter(void) | general |
| PyObject_HasAttr | 001944d8 | undefined PyObject_HasAttr(void) | general |
| PyObject_Call | 00194518 | undefined PyObject_Call(void) | general |
| PyErr_Format | 00194530 | undefined PyErr_Format(void) | general |
| PyObject_ClearManagedDict | 00194560 | undefined PyObject_ClearManagedDict(void) | general |
| PyObject_GetAttr | 00194588 | undefined PyObject_GetAttr(void) | general |
| PyObject_GetOptionalAttr | 00194598 | undefined PyObject_GetOptionalAttr(void) | general |
| PyMem_Malloc | 001945d0 | undefined PyMem_Malloc(void) | general |
| PyErr_WarnFormat | 001945d8 | undefined PyErr_WarnFormat(void) | general |
| PyObject_GC_UnTrack | 00194608 | undefined PyObject_GC_UnTrack(void) | general |

### openai-tiktoken 
**Binary:** _tiktoken.cpython-313-x86_64-linux-gnu.so 
**Format:** Executable and Linking Format (ELF) / x86:LE:64:default 
**Functions:** 3191 | **Risky:** 58 
| Function | Entry | Signature | Exploitation Class |
|----------|-------|-----------|-------------------|
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001da610 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| into_pyobject | 001e7a60 | undefined into_pyobject(void) | type-confusion |
| drop_in_place<core::option::Option<core: | 001e9750 | undefined drop_in_place<core::option::Option<core::result::R | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001ea1e0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<core::option::Option<core: | 001ee3c0 | undefined drop_in_place<core::option::Option<core::result::R | use-after-free |
| drop_in_place<core::option::Option<core: | 001f02d0 | undefined drop_in_place<core::option::Option<core::result::R | use-after-free |
| owned_sequence_into_pyobject | 001f0550 | undefined owned_sequence_into_pyobject(void) | type-confusion |
| drop_in_place<pyo3::err::PyErr> | 001f11d0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<core::option::Option<core: | 001f25e0 | undefined drop_in_place<core::option::Option<core::result::R | use-after-free |
| owned_sequence_into_pyobject | 001f26c0 | undefined owned_sequence_into_pyobject(void) | type-confusion |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001f2d00 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001f61d0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001f6ca0 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001f6cc0 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001f6ce0 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001f6cf0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<core::result::Result<pyo3: | 001f7fd0 | undefined drop_in_place<core::result::Result<pyo3::instance: | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001f8020 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| into_pyobject | 001f8fc0 | undefined into_pyobject(void) | type-confusion |
| drop_in_place<std::sync::poison::mutex:: | 001f9680 | undefined drop_in_place<std::sync::poison::mutex::MutexGuard | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001f97d0 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<std::sync::poison::PoisonE | 001f97f0 | undefined drop_in_place<std::sync::poison::PoisonError<std:: | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001f9840 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 001fbfb0 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 001fbfd0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| into_pyobject | 001fdfc0 | undefined into_pyobject(void) | type-confusion |
| drop_in_place<pyo3::err::err_state::PyEr | 001ff270 | undefined drop_in_place<pyo3::err::err_state::PyErrState::la | use-after-free |
| drop_in_place<pyo3::err::err_state::PyEr | 001ff310 | undefined drop_in_place<pyo3::err::err_state::PyErrStateInne | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 002000f0 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| drop_in_place<pyo3::err::PyErr::new<pyo3 | 00200820 | undefined drop_in_place<pyo3::err::PyErr::new<pyo3::exceptio | use-after-free |
| drop_in_place<pyo3::err::PyErr> | 00200840 | undefined drop_in_place<pyo3::err::PyErr>(void) | use-after-free |
| mmap | 0032acf0 | undefined mmap(void) | arbitrary-code |
| memcpy | 00385020 | void * memcpy(void * __dest, void * __src, size_t __n) | memory-corruption |
| PyErr_WriteUnraisable | 003850b0 | undefined PyErr_WriteUnraisable(void) | general |
| PyObject_GC_UnTrack | 003850b8 | undefined PyObject_GC_UnTrack(void) | general |
| PyObject_Size | 00385108 | undefined PyObject_Size(void) | general |
| PyObject_Str | 00385110 | undefined PyObject_Str(void) | general |
| PyObject_Repr | 00385118 | undefined PyObject_Repr(void) | general |
| PyObject_GetAttr | 00385128 | undefined PyObject_GetAttr(void) | general |
| PyObject_SetAttr | 00385130 | undefined PyObject_SetAttr(void) | general |
| PyObject_GetItem | 00385138 | undefined PyObject_GetItem(void) | general |
| PyObject_GetIter | 00385140 | undefined PyObject_GetIter(void) | general |
| PyErr_GivenExceptionMatches | 00385170 | undefined PyErr_GivenExceptionMatches(void) | general |
| PyObject_CallNoArgs | 003851a8 | undefined PyObject_CallNoArgs(void) | general |
| PyErr_Occurred | 003851e0 | undefined PyErr_Occurred(void) | general |
| PyObject_LengthHint | 003851e8 | undefined PyObject_LengthHint(void) | general |
| PyErr_SetRaisedException | 003851f0 | undefined PyErr_SetRaisedException(void) | general |
| PyErr_PrintEx | 00385220 | undefined PyErr_PrintEx(void) | general |
| PyErr_GetRaisedException | 00385228 | undefined PyErr_GetRaisedException(void) | general |
| PyErr_NewExceptionWithDoc | 00385238 | undefined PyErr_NewExceptionWithDoc(void) | general |
| PyObject_SetAttrString | 00385270 | undefined PyObject_SetAttrString(void) | general |
| PyObject_SetItem | 00385278 | undefined PyObject_SetItem(void) | general |
| PyObject_DelItem | 00385280 | undefined PyObject_DelItem(void) | general |
| PyErr_SetString | 003852b8 | undefined PyErr_SetString(void) | general |
| PyErr_SetObject | 003852c0 | undefined PyErr_SetObject(void) | general |
| malloc | 00385350 | void * malloc(size_t __size) | general |
| free | 00385360 | void free(void * __ptr) | memory-corruption |
| mmap64 | 003853b0 | void * mmap64(void * __addr, size_t __len, int __prot, int _ | arbitrary-code |

--- 
## Top 30 Exploitable Binaries (by risky-import count) 
| Binary | Category | Functions | Risky | Top Exploitable Targets |
|--------|----------|-----------|-------|------------------------|
