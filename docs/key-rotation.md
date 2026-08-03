# Key rotation

BioVault uses envelope encryption, so rotating the master key never requires
re-encrypting genomic data.

```
master KEK (env / KMS)  ──wraps──>  per-dataset DEK  ──encrypts──>  field data
```

Rotating the KEK rewraps N small data keys. The bulk ciphertext is untouched.

## Rotating the master KEK

1. **Generate the new KEK.**

   ```bash
   python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
   ```

2. **Stage it beside the current key.** Set `BIOVAULT_MASTER_KEK_NEXT` and
   `BIOVAULT_MASTER_KEK_NEXT_ID` (e.g. `kek-2`). The old KEK stays active so
   in-flight requests keep working.

3. **Rewrap.** For each dataset, unwrap the DEK under the old KEK and rewrap it
   under the new one:

   ```bash
   python -m biovault.scripts.rotate_kek --from kek-1 --to kek-2
   ```

   This calls `EnvelopeCipher.rewrap_data_key`. It reads and writes only the
   `wrapped_dek` column.

4. **Verify no keys remain under the retired KEK.**

   ```sql
   SELECT kek_id, count(*) FROM dataset_keys GROUP BY kek_id;
   ```

   Every row must report the new `kek_id` before continuing.

5. **Promote.** Move the new key into `BIOVAULT_MASTER_KEK`, set
   `BIOVAULT_MASTER_KEK_ID=kek-2`, and clear the `_NEXT` variables.

6. **Retire the old KEK** from the secret store.

## Why `kek_id` is stored on every wrapped key

Rotation is not atomic. `kek_id` lets step 4 answer "is any data still wrapped
under the old key?" with a single query, which is what makes it safe to retire
the old KEK. Without it, retiring a key is a guess.

## Rotating a per-dataset DEK

Rotating a DEK *does* require re-encrypting that dataset's fields, since the
DEK is what encrypts the data. This is the expensive path and is only needed if
a specific DEK is believed compromised. Scope is one dataset — that per-dataset
blast radius is the reason DEKs are per-dataset rather than global.

## Threats this does and does not address

**Addressed.** A leaked master KEK is contained once rotation completes: the
leaked key no longer unwraps anything. Envelope encryption makes that
containment cheap enough to actually perform on a schedule.

**Not addressed.** Rotation does not help against an attacker who captured
plaintext, nor against one holding both a DEK and that dataset's ciphertext.
Rotation limits future exposure; it cannot retract past disclosure.

## Production note

In this project the master KEK comes from an environment variable, which is
adequate for a synthetic-data demonstration. A real deployment holding genomic
data should keep the KEK in a KMS or HSM where the key material never enters
application memory, and perform wrap/unwrap as remote API calls. The
`EnvelopeCipher` interface is deliberately shaped to make that substitution
mechanical: replace the local `AESGCM` wrap/unwrap with KMS calls and nothing
above it changes.
