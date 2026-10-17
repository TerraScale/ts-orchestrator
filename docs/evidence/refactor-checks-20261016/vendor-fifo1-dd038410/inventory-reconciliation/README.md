# Inventory reconciliation for FIFO1

The broker receipt and published packet retain the original passing result.
The inventory adds scoped standard-execution credit while retaining the private
race/interleaving gaps. Twenty of 27 account groups now have scoped PASS
evidence; central closures remain zero.

During reconciliation, a derived summary reused the original summary filename.
The original was restored byte-for-byte from the published packet (SHA256
`7ad381e9a2d71f04ed260e95c85912eee43f386f669864c9ac18d63139d05d09`).
The derived version is preserved separately as `derived-receipt.json` (SHA256
`9229c88b87fc688b95207821009a5e8109a2a55c0c9c8bb82af8b51182f78fda`).
The primary broker receipt, raw log, packet and frozen FIFO were unchanged.
New receipt files now use exclusive creation. The accompanying provenance
record states the evidentiary limits of the filename incident.
