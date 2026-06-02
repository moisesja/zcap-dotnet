# Normative Compliance Test Matrix

Source baseline: `docs/ZCAP-LD-SPECIFICATION-REQUIREMENTS.md` section 10.

## Run

```bash
dotnet test tests/ZcapLd.Core.Tests/ZcapLd.Core.Tests.csproj --filter FullyQualifiedName~Compliance
```

## MUST Requirements

| Requirement ID | Test |
|---|---|
| MUST-01 | `NormativeUnitComplianceTests.Must01_RootContext_MustBeExactValue` |
| MUST-02 | `NormativeUnitComplianceTests.Must02_Root_MustContainRequiredFields` |
| MUST-03 | `NormativeUnitComplianceTests.Must03_Root_MustNotHaveAdditionalFields` |
| MUST-04 | `NormativeUnitComplianceTests.Must04_DelegatedContext_MustBeArrayWithZcapContextFirst` |
| MUST-05 | `NormativeUnitComplianceTests.Must05_DelegatedCapability_MustContainRequiredFields` |
| MUST-06 | `NormativeUnitComplianceTests.Must06_DelegatedCapability_MustHaveDelegationProof` |
| MUST-07 | `NormativeUnitComplianceTests.Must07_CapabilityChain_MustStartWithRootId` |
| MUST-08 | `NormativeUnitComplianceTests.Must08_CapabilityChain_MustEmbedImmediateParent` |
| MUST-09 | `NormativeIntegrationComplianceTests.Must09_Verifier_MustRejectDelegationSignedByUnauthorizedController` |
| MUST-10 | `NormativeIntegrationComplianceTests.Must10_Verifier_MustEnforceInvocationTargetAttenuation` |
| MUST-11 | `NormativeIntegrationComplianceTests.Must11_Verifier_MustRejectLessRestrictiveExpiration` |
| MUST-12 | `NormativeIntegrationComplianceTests.Must12_Verifier_MustRejectAllowedActionExpansion` |
| MUST-13 | `NormativeIntegrationComplianceTests.Must13_Verifier_MustLimitCapabilityChainLength` |
| MUST-14 | `NormativeIntegrationComplianceTests.Must14_Verifier_MustRejectExpiredDelegatedCapabilities` |
| MUST-15 | `NormativeUnitComplianceTests.Must15_DelegatedCapabilities_MustHaveExpiration` |
| MUST-16 | `NormativeUnitComplianceTests.Must16_InvocationProofPurpose_MustBeCapabilityInvocation` |
| MUST-17 | `NormativeUnitComplianceTests.Must17_DelegationProofPurpose_MustBeCapabilityDelegation` |
| MUST-18 | `NormativeIntegrationComplianceTests.Must18_Verifier_MustValidateEmbeddedChainWithoutNetworkDereference` |
| MUST-19 | `NormativeIntegrationComplianceTests.Must19_Verifier_MustRejectTamperedDelegationProofs` |
| MUST-20 | `NormativeIntegrationComplianceTests.Must20_Verifier_MustEvaluateAllChainCaveats` |
| MUST-21 | `NormativeIntegrationComplianceTests.Must21_Verifier_MustPersistRevokedCapabilitiesUntilExpiration` |
| MUST-22 | `NormativeIntegrationComplianceTests.Must22_Verifier_MustEnforceAttenuationSuffixDelimiterRules` |

## SHOULD Requirements

| Requirement ID | Test |
|---|---|
| SHOULD-01 | `NormativeUnitComplianceTests.Should01_RootId_ShouldUseRecommendedFormat` |
| SHOULD-02 | `NormativeUnitComplianceTests.Should02_DelegatedId_ShouldUseUrnUuidFormat` |
| SHOULD-03 | `NormativeIntegrationComplianceTests.Should03_Verifier_ShouldUseChainLimitOfTen` |
| SHOULD-04 | `NormativeIntegrationComplianceTests.Should04_Delegation_DoesNotThrowOnLongExpirationAtCreateTime` |
| SHOULD-05 | `NormativeUnitComplianceTests.Should05_CapabilityAction_AllowsApplicationDefinedActions` |
| SHOULD-06 | `NormativeUnitComplianceTests.Should06_Invocation_ShouldExposeIdField` |
| SHOULD-07 | `NormativeUnitComplianceTests.Should07_RevocationEndpoint_ShouldBeSupported` |
