| Function | Baseline gas | Optimized gas | Saved |
|---|---:|---:|---:|
| registerEntity(hospital) | 315957 | 69657 | 78.0% |
| registerEntity(doctor) | 281613 | 69645 | 75.3% |
| registerEntity(patient) | 281613 | 69657 | 75.3% |
| registerEntity(device) | 281637 | 69657 | 75.3% |
| issueCertificate | 509333 | 97958 | 80.8% |
| grantAccess | 167692 | 50796 | 69.7% |
| requestAccess | 137324 | 33369 | 75.7% |
| revokeAccess | 118092 | 24001 | 79.7% |
| register 4 entities (4 txs vs 1 batch tx) | 1160820 | 217336 | 81.3% |

New in the optimized contract (no baseline equivalent):

| Function | Gas |
|---|---:|
| grantAccess(1h) | 50921 |
| suspendEntity | 30811 |
| setEmergencyPolicy | 47654 |
| emergencyAccess | 39745 |
