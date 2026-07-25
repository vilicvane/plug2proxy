# plug2proxy quiche patch

This is the crates.io source for quiche 0.29.3 with two focused stream FIN
fixes.

`SendBuf::is_complete()` previously treated all data bytes being acknowledged
as acknowledgement of the stream FIN. That is insufficient for a zero-length
FIN: an older ACK can arrive after the FIN is queued and cause the stream to be
collected before the FIN packet is acknowledged. If that packet is then
declared lost, quiche has already discarded the stream state needed to
retransmit it.

The patch tracks acknowledgement of a STREAM frame carrying `fin=true`
separately and requires both the byte range and FIN to be acknowledged before
normal stream completion.

A second failure occurs when the application queues a zero-length FIN while a
non-final retransmit range is already flushable. Emitting that range empties
the data buffer, which previously removed the stream from the flushable queue
even though the FIN still needed its own STREAM frame. The patch keeps the
stream scheduled for one additional frame whenever the emitted frame did not
carry an already-queued FIN.

Regression coverage:

- `send_buf::tests::zero_length_fin_requires_its_own_ack`
- `tests::stream_zero_length_fin_survives_non_fin_retransmit`
- the existing stream completion test now explicitly acknowledges the FIN
