| Function | Baseline gas | Optimized gas | Saved |
|---|---:|---:|---:|
| registerEntity(hospital) | 315957 | 69635 | 78.0% |
| registerEntity(doctor) | 281613 | 69623 | 75.3% |
| registerEntity(patient) | 281613 | 69635 | 75.3% |
| registerEntity(device) | 281637 | 69635 | 75.3% |
| issueCertificate | 509333 | 97936 | 80.8% |
| grantAccess | 167692 | 50796 | 69.7% |
| requestAccess | 137324 | 33370 | 75.7% |
| revokeAccess | 118092 | 23979 | 79.7% |
| register 4 entities (4 txs vs 1 batch tx) | 1160820 | 217336 | 81.3% |

New in the optimized contract (no baseline equivalent):

| Function | Gas |
|---|---:|
| grantAccess(1h) | 50921 |
| suspendEntity | 30922 |
| setEmergencyPolicy | 47654 |
| emergencyAccess | 39856 |
