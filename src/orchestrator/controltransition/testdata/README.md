# Public acknowledgement fixture

`pin-receipt.json` contains an owner public key, a signed synthetic transition
plan, and its source host's signed pin receipt. It contains no private keys.
The signatures and plan are fixed so every fuzz worker can verify the same
receipt while mutations target only its encoding.

The dates describe historical evidence. `VerifyPinReceipt` deliberately checks
the receipt's dates against the signed plan rather than the current wall clock.
Live agreement checks remain separate. The synthetic hashes and bucket names
do not identify admitted production resources.
